# RFC 0004: Handles (unique usernames mapped to identity keys)

| | |
|---|---|
| **Status** | Proposed. Open for comment for at least 14 days (GOVERNANCE.md, "The RFC process"); security reviewers must comment. Nothing here is implemented. |
| **Date** | 2026-11-23 |
| **Discussion** | [#2](https://github.com/ix-infrastructure/Peer2Peer/issues/2) |
| **Applies to** | [protocol.md](../protocol.md) v3 draft 3, protocol 3.1: two new proof kinds in §2.6, a new §2.9 "Handles", and amendments to the display rules in §2.1 and §7 |
| **Wire impact** | Phases 1–2: none on the peer wire; two new proof kinds inside the existing `proofs` array, which every released client already tolerates (§11.2). Phase 3: one new signed-object type, used only in registrar logs. Phase 4: one optional, non-critical identity-document field, rolled out in two steps |

Words in capitals (MUST, SHOULD, MAY) are used as in RFC 2119. Section signs (§) without a file name point into [protocol.md](../protocol.md); "R§" points into this RFC.

## 1. Summary

Today a person shows up as `name@fingerprint`, for example `ann@k7f2-qx9a-3m4n-5p6q`. The `name` is self-chosen and not unique, so the 80-bit fingerprint carries all the uniqueness. That is safe, but people can't remember it, say it aloud or type it.

This RFC adds **handles**: short, human-readable names, each of which maps to **exactly one userId** at any moment. Peer2Peer has no accounts and no central server, so a handle takes its uniqueness from a namespace that is already globally unique. There are four kinds:

| Kind | Typed as | Unique because | Who vouches | Needs new infrastructure |
|---|---|---|---|---|
| `dns` | `ann.example.org` | DNS | whoever controls the DNS name | no |
| `web` | `ann@example.org` | DNS + the host's paths | whoever runs `https://example.org` | no (one static file) |
| `gh` | `gh:octocat` | GitHub logins | the GitHub account | no |
| `reg` | `ann@names.example.net` (a registrar host) | the registrar's log | first come, first served, recorded in an append-only transparency log | yes: a registrar (Phase 3) |

Three rules hold for every kind:

1. **Two-way binding.** A handle is verified for an identity only when the identity's own signed document claims the handle **and** the handle's authority (DNS, the web host, GitHub, the registrar) names that identity, and only that one (R§5).
2. **The client verifies; nothing else is trusted.** Each client fetches the counterpart from the authority itself. A relay is never asked to resolve a handle, and nothing a relay or a peer says about a handle is believed (R§7).
3. **A handle is display and discovery, never authorisation.** Every decision still compares full userIds (§2.1). A handle that changes which key it points to is shown loudly and never followed silently, unless the user already accepted a rotation between those two keys (R§9).

Domain and GitHub handles reuse the existing `dns` and `github` proofs, and need no new server, so they ship first. The community registrar comes after, as one namespace among many that anyone can run.

## 2. Motivation

- **Fingerprints are hard to use.** People read `ann@k7f2-qx9a-3m4n-5p6q` aloud on calls, paste it into chats and compare it by eye. A handle such as `ann.example.org` or `gh:ann` can be remembered and typed, and still gets checked.
- **Organisations want names they control.** A team that owns `example.org` wants to give its people handles under it, and take them back when someone leaves, without running a Peer2Peer server.
- **Lookalikes are the main social attack on an open network.** Anyone can pick `name: "ann"`. Proofs (§2.6) already help, but they are shown as a side note ("✓ github: ann"). Making a verified handle the primary display name, with an explicit badge that names who vouches for it, lets people tell the real Ann from a copy at a glance.
- **Stability.** A handle points at the userId, which survives new devices, new sessions and client updates. Through the rotation rules (R§9), it survives an identity rotation too.

### 2.1 Constraints

- **No accounts, no central authority.** The project must not run the only database that decides who is who. Every namespace here is either an existing global one (DNS, GitHub) or a registrar anyone can run under their own domain.
- **The userId stays the identity.** Handles are optional. A client without handle support interoperates fully, and a user without a handle loses nothing.
- **Hostile relays and peers** (the open-network assumption). The design must fail closed: when in doubt, no badge.

## 3. Goals and non-goals

### 3.1 Goals

- **G1.** A handle resolves to at most one userId, and a client can check that itself.
- **G2.** No relay, peer or registrar can make a client show a handle for an identity that the handle's authority doesn't name, or that never claimed the handle.
- **G3.** A handle changing hands (a domain lapses, an account is taken over, a registrar misbehaves) never silently redirects messages or trust. Existing friendships stay bound to the userId.
- **G4.** A handle follows its owner across an identity rotation the user accepted, without the owner losing it.
- **G5.** The display makes impersonation hard: canonical ASCII forms, punycode for international domains, confusable warnings, and a badge that names the authority.
- **G6.** Domain and GitHub handles need no new infrastructure.

### 3.2 Non-goals

- **Handles never authorise.** They don't make anyone a friend, grant a capability, admit anyone to a circle, or skip the hold rule. §8.2's rule, "a provider can only add a badge", applies to handles too.
- **No global root.** There is no "official" registrar, and no client hard-codes one as more trusted than another.
- **Not a secret.** Handles and the bindings behind them are public by design.
- **No email handles.** Verifying an email needs a server that sends mail (v2 did this, V2); this RFC doesn't bring that back (R§13).
- **No Unicode handles.** Handles are ASCII. International domains are supported, but only ever shown in their ASCII (punycode) form (R§4.3).

## 4. Handle syntax

### 4.1 Canonical forms

Every handle has exactly one canonical string, with its kind prefix. The prefix is always part of the canonical form, so two kinds can never produce the same string.

| Kind | Canonical form | Example | Proof `claim` (§2.6) |
|---|---|---|---|
| `dns` | `dns:<domain>` | `dns:ann.example.org` | `ann.example.org` |
| `web` | `web:<local>@<host>` | `web:ann@example.org` | `ann@example.org` |
| `gh` | `gh:<login>` | `gh:octocat` | `octocat` (the existing `github` proof kind) |
| `reg` | `reg:<local>@<host>` | `reg:ann@names.example.net` | `ann@names.example.net` |

`gh` is the handle spelling of the existing `github` proof kind; the proof keeps `kind: "github"`. `dns` handles are exactly the existing `dns` proof.

### 4.2 Typed forms

People type handles without the prefix. A client maps typed input to a canonical form like this:

- `gh:<login>` → `gh`.
- `<local>@<host>` → `web` or `reg`, depending on the host: `reg` if the host is a registrar (its host descriptor says so, R§6.4, or the client has pinned it as one), otherwise `web`. A `user@host` string is one handle whichever kind it turns out to be: `web:ann@h` and `reg:ann@h` are never two different handles (R§6.4, downgrade).
- a bare domain with at least one dot → `dns`.
- an explicit prefix (`dns:`, `web:`, `reg:`) is always accepted.
- An optional leading `@` is dropped (`@ann@example.org` = `ann@example.org`).
- Anything else is not a handle. In particular, a string that parses as a §2.1 address (`name@xxxx-xxxx-xxxx-xxxx`), a userId or a petname is resolved as today, before any handle lookup, and a client MUST NOT send a handle lookup for it. This keeps typos of local names from leaking to DNS.

### 4.3 Normalisation and character set

A client normalises input in this order, and refuses the input as `handle-invalid` if any step fails. The output is pure ASCII.

1. **Unicode normalisation:** `toNFKC_Casefold` (Unicode NFKC with default case folding, UAX #31 / UAX #44). This folds fullwidth letters, compatibility forms and case.
2. **Domain part** (`dns` domain; `web`/`reg` host): UTS #46 processing, non-transitional, with `CheckHyphens`, `CheckBidi`, `CheckJoiners`, `UseSTD3ASCIIRules` and `VerifyDnsLength` all on, producing A-labels (`xn--…`). Then:
   - it MUST match core's existing `DOMAIN_RE` (`packages/core/src/v3/proofs.ts`): LDH labels, a TLD that starts with a letter, at most 253 characters;
   - it MUST NOT be an IP literal, MUST NOT contain a label starting with `_`, and MUST NOT end in a special-use or non-public suffix (`localhost`, `local`, `internal`, `home.arpa`, `onion`, `test`, `invalid`; RFC 6761, RFC 6762, RFC 7686, RFC 8375). Test vectors use `example.org`, `example.net` and `example.com`, which are ordinary public names;
   - a trailing dot is removed.
3. **Local part** (`web`/`reg`): `^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,31}$`: 1–32 characters, lowercase letters, digits and single inner hyphens. The local part MUST NOT start with `xn--` or have `--` in positions 3–4, so it can never pose as punycode.
4. **GitHub login:** core's existing `GITHUB_HANDLE_RE`, `^[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,38}$`. GitHub logins are case-insensitive; the canonical form is lowercase.
5. **Length for display:** a canonical handle longer than **64 characters** is not a handle. (A longer `dns` proof still verifies as a proof and is shown as one, as today.)

**Comparison** is byte equality of canonical forms. A proof's `claim` MUST already be canonical; a proof whose claim isn't is `malformed` (this is today's rule for `dns` and `github`, extended to `web` and `reg`).

**International domains** are shown only as A-labels (`ann.xn--bcher-kva.example`), never as U-labels, in every view. A client MAY show the U-label in a detail view, in parentheses after the A-label and marked "(unicode, check carefully)". Showing only the A-label removes the whole class of mixed-script and whole-script confusables at the cost of readability for those domains, which we accept.

### 4.4 Confusable skeletons

ASCII still has lookalikes (`rn`/`m`, `l`/`1`, `0`/`o`, `vv`/`w`, `cl`/`d`). For warnings only (never for comparison), a client computes a **skeleton** of each canonical handle, of every petname and of every self-chosen `name` it displays:

1. take the canonical form without its kind prefix;
2. replace, left to right and repeatedly until nothing changes: `rn`→`m`, `vv`→`w`, `cl`→`d`, `0`→`o`, `1`→`l`, `i`→`l`, `5`→`s`;
3. remove `-`, `.` and `_`.

Two different canonical strings with the same skeleton are **lookalikes** (R§8.4). The map is short and explicit on purpose, so that every implementation computes the same skeleton; a test vector file fixes it (R§11.4). We don't use the full UTS #39 skeleton because handles are ASCII after R§4.3, and the full table maps ASCII mostly to itself.

## 5. The binding rule

A handle `H` of kind `k` is **verified for userId `U`** at time `t` when all of these hold:

1. **The identity claims it.** `U`'s identity document, as the client holds it (the highest chain-consistent head, §2.5), carries in `proofs` a proof `P` with `P.kind` = the kind's proof kind (`dns`, `web`, `github`, `reg`) and `P.claim` = `H`'s claim, and `P` passes §2.6 rules 1, 2 and 4 against that document.
2. **The authority names it, and only it.** The counterpart for `H`, fetched by this client from `H`'s authority (R§6), names `U` and no other userId, and passes the kind's §2.6 rule 3.
3. **The identity is live.** The head is not a rotation's final version (P3 "Rotation"), the identity is not in a rotation conflict, and the client has not failed closed for it (more than 60 days past `exp`, §2.5).
4. **The answer is fresh.** Both checks are within their cache lifetimes (R§10).

Why both directions:

- Rule 1 alone would let anyone claim `ann.example.org` in their own document.
- Rule 2 alone would let the owner of `evil.example` point `ceo.evil.example` at a victim's userId, so that the victim appears to friends under a name they never chose. Requiring the identity's own signed claim stops that.

**Exactly one.** If the authority's answer names more than one userId (two `p2p-proof=` TXT values, say), the handle is `ambiguous` and is verified for nobody. If two identities a client knows both claim `H` and the authority names one of them, `H` is verified for that one only, and the other identity's claim is simply an unverified proof.

## 6. Per-kind resolution

Each kind defines a **forward lookup** (handle → userId, for `p2p whois`, `invite --to` and `send --to`) and a **reverse check** (an identity document's proof → the counterpart, for display). Both end in the same R§5 rule.

### 6.1 `dns`: domain handles by DNS TXT

- **Record (unchanged from §2.6):** TXT at `_p2p.<domain>`, with one string (after joining a record's character-strings) equal to `p2p-proof=<userId>`.
- **New, optional relay hints:** further TXT records at the same name, `p2p-relay=<canonical relay URL>` (§5.1), at most 5. Hints are only where to look for the identity document first. They are never trusted: the document is self-certifying, and once fetched, its own `relays` list takes over (§5.6).
- **Forward lookup:** query TXT `_p2p.<domain>`; collect every `p2p-proof=` value; exactly one distinct, well-formed userId, else `ambiguous` (several) or `not-found` (none). Fetch the document (R§7 step 4) and apply R§5.
- **CNAME:** a CNAME at `_p2p.<domain>` is followed by the resolver as usual. The authority is still `<domain>`: whoever controls that name chose the CNAME.
- **DNSSEC:** a client MAY validate DNSSEC, or use a validating resolver over DoH (RFC 8484). If the answer validated, the client records `dnssec: true` and shows it in detail views. It doesn't change the badge, because most domains aren't signed and we don't want two classes of handle.
- **What it's for:** a person with their own domain, or an organisation that adds one TXT record per person (`_p2p.ann.example.org`), or delegates a subdomain.

### 6.2 `web`: handles served over HTTPS

- **Location:** `https://<host>/.well-known/p2p/handles/<local>` (RFC 8615). The issue proposed `/.well-known/p2p/<local>`; the `handles/` level leaves room for the host descriptor (below) next to it.
- **Fetch rules** (all MUST):
  - HTTPS on port 443 only, with normal WebPKI certificate validation;
  - **no redirects** (a 3xx is `not-found`), no cookies, no authentication, no `Referer`, a fixed `User-Agent` (`p2p-handle/1`) with no client version;
  - the host MUST resolve only to public unicast addresses: a client refuses loopback, private (RFC 1918, RFC 4193), link-local, CGNAT, multicast and unspecified addresses, before connecting and for the address it actually connects to. This stops a handle from turning a client, or an agent's machine, into a probe of its local network or a cloud metadata service;
  - response `200`, `Content-Type: application/json`, at most **4 KiB**, within **10 s**; anything else is `unreachable` (5xx, timeouts) or `not-found` (404, 410, a wrong body).
- **Body:**
  ```json
  { "v": 1, "handle": "ann@example.org", "userId": "p2p:…", "relays": ["wss://…"] }
  ```
  - `handle` MUST equal the canonical claim. This binds the answer to the question, so a misconfigured catch-all route or a CDN cache mix-up can't hand one person's binding to another handle.
  - `relays` is optional, at most 5, hints only (as in R§6.1).
  - Unknown fields are ignored (the 3.1 must-ignore rule). An unknown `v` is `unsupported`: no badge, and not treated as a negative answer.
- **Proof in the document:** `kind: "web"`, `claim: "ann@example.org"`, `loc: "https://example.org/.well-known/p2p/handles/ann"`. §2.6 rule 4 for `web`: `loc` is exactly that URL. Rule 3 for `web`: the body above names `D.iss`.
- **Host descriptor (optional):** `https://<host>/.well-known/p2p/host.json`, same fetch rules:
  ```json
  { "v": 1, "mode": "web" | "registrar", "log": { … } }
  ```
  Absent means `web`. `registrar` makes every handle on this host a `reg` handle (R§6.4).
- **What it's for:** an organisation hands out `ann@example.org` by putting one small file per person on its website. Offboarding is deleting the file.

### 6.3 `gh`: GitHub handles

- **Reverse check (unchanged, §2.6):** the proof's `loc` is `https://gist.github.com/<login>/<gist id>`, the gist's owner is `<login>`, and a file in it contains the exact proof JWS.
- **New: binding to the numeric account id.** GitHub logins can be renamed and then registered by someone else. The client records the account's numeric `id` the first time it verifies a `gh` handle, and from then on treats a different numeric id behind the same login as a **change of hands** (R§9.2), even if the new owner publishes a valid proof. The gist API already returns `owner.id`; core's `ProofFetchers.github` returns it alongside `owner`.
- **Forward lookup:** a login alone doesn't say which gist holds the proof, so a handle that should be findable by `gh:<login>` publishes a gist with a file named exactly **`p2p-handle.json`**:
  ```json
  { "v": 1, "proof": "<the p2p-proof+jws>", "relays": ["wss://…"] }
  ```
  The client:
  1. `GET https://api.github.com/users/<login>/gists?per_page=100` (first page only);
  2. keeps the public gists that have a file named `p2p-handle.json`. Exactly one, else `ambiguous` or `not-found`;
  3. fetches that gist (`GET /gists/<id>`), checks `owner.login` (case-insensitively) and records `owner.id`;
  4. reads `proof`, takes `U = proof.iss`, and checks that `proof.loc` is this gist's canonical URL;
  5. fetches `U`'s document and applies R§5. Rule 1 then finds the same proof JWS in the document.
  Existing `github` proofs whose gist has no `p2p-handle.json` keep verifying in the reverse direction, so they are shown as handles; they just can't be found by `gh:<login>` alone.
- **Rate limits:** GitHub allows unauthenticated clients about 60 API calls an hour per IP. Clients cache aggressively (R§10). A client MAY let the user configure a GitHub token for lookups, kept in the OS keychain and sent only to `api.github.com`; it MUST say that lookups are then tied to that GitHub account.

### 6.4 `reg`: community registrar handles

A registrar is a web host whose host descriptor says `"mode": "registrar"`. It gives handles to people with neither a domain nor a GitHub account: first come, first served, rate-limited. **It can't sign a binding by itself:** every binding is a statement signed by the user's identity key, and the registrar only orders those statements in a public, append-only log.

#### 6.4.1 The log

- **Shape:** a Merkle tree log in the C2SP `tlog-tiles` format, with checkpoints in the C2SP `signed-note` format, signed by the registrar's Ed25519 log key. These are the formats Certificate Transparency's static logs and Go's checksum database use, with existing open-source verifiers and monitors.
- **Witnesses:** each checkpoint is cosigned by independent witnesses (C2SP `tlog-witness`). A witness cosigns only a checkpoint that is consistent with every earlier checkpoint it has seen from that log. A client accepts a checkpoint only with the log key's signature **and** at least `k` cosignatures from its witness list (default `k = 1` at launch, configurable; the list ships with the client and is user-editable). This is what stops a registrar from showing different people different histories (a split view).
- **Descriptor:** `"log": { "origin": "<log origin line>", "key": "<signed-note verifier key>", "witnesses": [ … ]? }` in `host.json`. A client pins the log key on first use; a changed key is a registrar change (R§9.2) and every handle on that host loses its badge until the user accepts the new key.
- **Merge delay:** an accepted entry appears in a checkpoint within 1 hour.

#### 6.4.2 Entries

Each entry is one compact JWS, `typ: "p2p-handle-reg+jws"`. Two signers are possible:

- **User entries**, `kid: "ik"`, signed by the identity key that holds (or is claiming) the handle:
  ```
  { "op":"register"|"renew"|"release"|"move", "handle":"ann@names.example.net",
    "iss":"<userId>", "ik":"<b64u>", "prev":"<jwsHash of this handle's previous entry>" | null,
    "relays":["wss://…"]?, "to":"<userId>"?, "accept":"<JWS by the new ik>"?, "iat":<s> }
  ```
- **Registrar entries**, `kid: "log"`, signed by the log key, for policy actions only:
  ```
  { "op":"expire"|"suspend"|"reinstate", "handle", "prev":"<jwsHash>", "reason":"inactive"|"policy"|"dispute", "ref":"<https URL of the public decision>"?, "iat":<s> }
  ```

Every entry for a handle names the previous one in `prev`, so a handle's entries form a chain inside the log. A client (or monitor) replays a handle's chain to find its current holder:

| Op | Valid when | Effect |
|---|---|---|
| `register` | the handle is unbound (never registered, or released/expired and past its 90-day quarantine); `prev` is the last entry or `null`; the registrar's rate limits passed | binds to `iss` |
| `renew` | signed by the current holder | keeps the binding; resets the inactivity clock; a new `relays` replaces the hints |
| `release` | signed by the current holder | unbinds; 90-day quarantine |
| `move` | signed by the current holder's `ik`, with `to` and an `accept` JWS (`typ: "p2p-handle-accept+jws"`, signed by the new identity's `ik` over `{handle, from, to, iat}`) | binds to `to` after a **72-hour hold** (below) |
| `expire` | the holder's last `register`/`renew` is more than **400 days** older than this entry's `iat` (renewals are due yearly, with a 35-day grace) | unbinds; 90-day quarantine |
| `suspend` | always (it's policy), but logged with `reason` and, for `policy`/`dispute`, a public `ref` | no holder is shown while suspended; nobody can register it |
| `reinstate` | the handle is suspended | restores the binding to the holder before the suspension |

The timing rules are checked by everyone from the entries themselves. A premature `expire`, or an entry that doesn't chain, is **provable registrar misbehaviour**: clients ignore it (the binding continues for them), and a monitor can publish the evidence.

**The 72-hour hold on `move`.** A thief who holds the identity key could sign a `move` to its own key. For 72 hours after a `move` enters the log, the handle shows as "moving" with no badge on either identity, and the old holder may append a second, conflicting `move` or a `renew` (a **contest**). A contested move freezes the handle as `disputed` until a later entry chain settles it (the registrar's `dispute` process, logged). This mirrors the rotation rules (§2.8, P3): when two parties both hold the key, the network can't tell who is honest, so it applies neither and shows the conflict. The owner's own client watches the log for its handles (below), so it sees a `move` it didn't make within its monitoring interval.

**Renewal** is automatic: a key-holding device of the holder signs a `renew` every 11 months while it is online.

#### 6.4.3 Resolving a `reg` handle

- **Answer:** the `web` URL for the handle (`/.well-known/p2p/handles/<local>`) returns, for a registrar:
  ```json
  { "v": 1, "handle": "ann@names.example.net", "userId": "p2p:…", "relays": ["wss://…"],
    "log": { "checkpoint": "<signed note with cosignatures>", "entries": [ { "jws": "…", "index": 123, "proof": ["<b64u hash>", …] } ] } }
  ```
  `entries` is the handle's chain, oldest first, each with its inclusion proof against `checkpoint`. A registrar MAY truncate the chain at the latest `register` (older history then comes from the tiles).
- **The client checks:**
  1. the checkpoint's signature (pinned log key) and at least `k` witness cosignatures;
  2. if it holds an earlier checkpoint of this log, a consistency proof to the new one (fetched from the tiles), so the log only grew;
  3. each entry's inclusion proof, signature (user `ik` or log key, by `kid`) and the chain rules above;
  4. that the replayed holder equals `userId`, and there is no `move` within its hold or a dispute;
  5. then R§5 with the document (whose `reg` proof has `loc` = the handle URL).
- **What a client can't check from one answer:** that no *later* entry exists than the ones served. A registrar could serve a stale binding. That can only show an earlier holder; it can't put a new key behind the handle, because a new key needs a `register`, `move` or `expire` entry, which is in the log. Freshness comes from monitoring:
  - **Self-monitoring:** each holder's client fetches the log's new tiles at least once a day and scans them for entries about its own handles. A `move`, `release`, `expire` or `suspend` it didn't expect alerts its user. Tiles are static files, so this is cheap, and it doesn't reveal which handle is being watched.
  - **Third-party monitors** may watch whole logs; anyone can run one.
- **Downgrade:** once a client has seen a host as a registrar, it pins that, and it refuses `web`-style answers (no `log`) from that host as `not-found` (like HSTS). A host can't switch from `registrar` to `web` without every pinned client noticing. A client also refuses a `web` proof for `user@host` when `host` is pinned as a registrar, and the other way round.

#### 6.4.4 Registration API

- `POST https://<host>/v1/handles` with the `register` (or any user op) JWS, plus a proof of work in the same form as §5.5, at the difficulty the registrar's descriptor advertises.
- Response: `202` with the entry's `jwsHash` and a signed promise (log key) to include it within the merge delay; or `409` (taken), `429` (rate limit), `403` (reserved or policy), with a machine-readable reason.
- The client never sends anything to the registrar except the entry and the proof of work: no identity document, no relay list beyond the entry's own hints.

#### 6.4.5 Naming policy (reference registrar defaults)

These are defaults for the reference registrar, not protocol rules. Every registrar publishes its policy at `https://<host>/.well-known/p2p/policy` (human-readable), and clients link to it from the badge's detail view.

- **Length:** 3–32 characters (R§4.3 local-part rules). One- and two-character names are reserved.
- **Reserved:** names that imply authority or are confusable with protocol words: `admin`, `root`, `support`, `security`, `abuse`, `help`, `staff`, `official`, `system`, `relay`, `p2p`, `peer2peer`, `registrar`, `postmaster`, `hostmaster`, `webmaster`, `noreply`, and any name whose skeleton (R§4.4) equals one of these.
- **Rate limits:** at most 3 handles per userId per registrar, and at most 1 `register` per userId per 24 hours. Identities are cheap (§5.5), so these only slow a careless squatter; the real limits are per-IP limits and proof of work that rises under load, and short names cost more work than long ones (difficulty +2 bits per character below 6).
- **Inactivity:** a handle expires 400 days after its last `register`/`renew`, then sits in a 90-day quarantine.
- **Disputes and trademarks:** a written, public process. Every outcome is a logged `suspend`/`reinstate`/`expire` with a `ref` to the public decision. The registrar never re-points a handle to a claimant directly: after an `expire`, the claimant registers it like anyone else, and every client that had pinned the old binding sees a change of hands (R§9.2).

## 7. Resolution procedure

`resolve(H)` in a client, for forward lookups:

1. **Parse and normalise** H (R§4). Refuse invalid input locally; send nothing.
2. **Fetch the counterpart from the authority directly** (R§6): the client's own DNS resolver, the web host, GitHub, or the registrar. When the user's transport is Tor (RFC 0001 §7), HTTPS lookups go through Tor with a fresh circuit per authority, and DNS lookups go through Tor's resolver or are refused. A client MUST NOT ask a relay, a peer or an extension to resolve a handle, and MUST NOT accept a binding a peer sent it (for example in a message, a status or an invite) as verified.
3. **Read the claimed userId `U`** and the relay hints. If `U` isn't a well-formed userId, the answer is `not-found`.
4. **Get `U`'s identity document:** from the local cache if held; otherwise from the hinted relays (§5.6 `GET /v3/identity/<userId>`), checking that it is `U`'s, self-certifying and chain-consistent; then refresh from every relay the document itself lists (§5.6), as for any identity. A hinted relay can withhold the document (the lookup fails as `unreachable`), but can't substitute another identity's, because `iss` must equal `U` and the document must verify under its own `ik`.
5. **Apply R§5**, including that `U`'s document carries the proof.
6. **Compare with what the client has pinned** (R§9): `new`, `same` or `changed`.
7. **Return** `{handle, kind, authority, userId, status, verifiedAt, expiresAt, dnssec?}`, where `status` is `verified`, `changed`, `moving`, `disputed`, `ambiguous`, `not-found`, `unsupported`, `unreachable` or `invalid`.

The reverse check, for display of a document's proofs, is steps 2–6 starting from the proof's `loc`.

**Definitive and transient failures.** `not-found`, `ambiguous`, a mismatch and `changed` are **definitive**: the badge goes at once. `unreachable` (timeouts, 5xx, SERVFAIL, GitHub rate limiting) is **transient**: the last verified state is kept within the grace period (R§10).

**When lookups happen.** A client looks a handle up only:
- on an explicit user command (`whois`, `invite --to`, `send --to`, `handle check`);
- for the primary handle of each friend and circle-mate, on the recheck schedule (R§10), as allowed by the user's `handles.verify` setting (R§12);
- never because a peer's message, status, profile or session text contains a handle-shaped string, and never on an agent's request without the user's command. A peer can't make a client contact a host of the peer's choosing just by mentioning it.

## 8. Display rules

### 8.1 What a contact is shown as

In order, the first that applies:

1. the user's **petname** for that userId (local; petnames always win);
2. the contact's **primary verified handle**, with its badge;
3. the §2.1 address, `name@fingerprint`.

The **primary handle** is the first proof in the document's `proofs` array, in array order, that verifies as a handle (R§5). The owner orders their proofs to choose it. This needs no new document field.

Wherever a petname is shown, detail views also show the verified handle and the fingerprint.

### 8.2 Badges

The badge is rendered by the client from its own verified state, never from text a peer controls, and it always names the kind and the authority:

| Kind | Badge (terminal, ASCII) | Authority shown |
|---|---|---|
| `dns` | `ann.example.org [dns example.org]` | the registrable domain (eTLD+1, by the Public Suffix List) |
| `web` | `ann@example.org [web example.org]` | the host's registrable domain |
| `gh` | `gh:octocat [github]` | `github` |
| `reg` | `ann@names.example.net [reg names.example.net]` | the registrar host, in full |

- **Why the registrable domain:** `ann.example.org.evil.net` shows as `[dns evil.net]`, so the part that looks trustworthy can't hide who actually vouches for it.
- **Why `reg` names the registrar:** a community registrar vouches only for "first to register", unlike an organisation's domain. The badge must make that difference visible, and `reg` handles from different registrars must never look alike.
- **Graphical clients** MAY use a check mark and an icon per kind, but MUST keep the kind and authority as text next to it, and MUST NOT rely on colour alone. Peer text can't carry a fake badge: self-chosen names are ASCII already (§2.1), and the sanitizer (§4.3) MUST remove `✓`, `✔`, `☑`, `🗸` and `✅` from any other peer text shown on the same line as a contact (labels, statuses, profile fields).
- **Machine output** (`--json`, the Claude Code mod, the Codex bridge): `{"handle":"web:ann@example.org","kind":"web","authority":"example.org","status":"verified"}`. Agents get handles only in canonical ASCII, wrapped as peer data as today.

### 8.3 Where the fingerprint stays

§2.1 says clients MUST show `fp` wherever they show `name`. This RFC amends it:

- In **compact lists** (friends, statuses, session pickers), a verified handle with its badge MAY stand in for `name@fp`.
- In every **security decision** (approving an invite or a join, accepting a rotation, trusting a sender or circle, confirming a changed handle, R§9.2) and every **detail view** (`whois`, profile), the client MUST show the full address with the fingerprint next to the handle.
- An **unverified** name never gets a badge, and is always shown with its fingerprint. A self-chosen `name` that has the shape of a handle (it contains a `.`) is shown in quotes, `"ann.example.org"@k7f2-qx9a-3m4n-5p6q`, so it doesn't read as a domain.

### 8.4 Lookalike warnings

When a handle is first verified for a contact, when the user resolves a handle, and whenever the contact list changes, the client compares skeletons (R§4.4) across every displayed handle, petname and name. When two different strings share a skeleton:

- both entries get a `[lookalike]` marker in lists;
- any security decision involving either shows a warning that names the other contact, with both fingerprints;
- a petname is never auto-suggested from a lookalike.

### 8.5 Two friends with the same display name

Self-chosen names collide all the time (two friends called `ann`). Today that is resolved by the fingerprint. With handles:

- **The same self-chosen `name`, no handles:** shown as `ann@k7f2-…` and `ann@m3x9-…`, as today. The client offers to set a petname for each the first time the collision appears. A bare `p2p send --to ann` is refused as ambiguous and lists both, with fingerprints; it never picks one.
- **One has a verified handle:** `ann.example.org [dns example.org]` and `ann@m3x9-…`. Still refused when addressed by the bare `ann`; addressing by the handle works.
- **Both claim the same handle:** at most one can verify (R§5, "exactly one"). The other shows as `name@fp` with "claims ann.example.org (not verified)" in detail views. If the authority names neither, neither gets a badge.
- **A handle equals someone else's petname:** the petname wins on its contact, and the handle's contact is shown with its handle; both get `[lookalike]` (their skeletons are equal).

## 9. Pinning, changes and rotation

### 9.1 What a client pins

For each handle it has verified, a client stores locally `{handle, userId, firstSeen, lastVerified, ghAccountId?, registrarLogKey?, lastCheckpoint?}`. The pin is the client's memory that "`ann.example.org` meant this key". It is never sent anywhere.

### 9.2 A handle that now points elsewhere

When `H` was pinned to `U` and now resolves (verified) to `V ≠ U`:

- **If the user has accepted a rotation `U → V`** (§2.8, P3: the friendship or circle standing was carried over after asking the user, and no conflicting rotation is known), the handle **follows**: the pin moves to `V`, and the detail view says "moved with the rotation on <date>".
- **Otherwise it's a change of hands:**
  - `U` loses the badge (the authority no longer names it); its friendship, trust and circle standing are untouched, because they are bound to `U`;
  - `V` gets **no** badge for `H` until the user confirms;
  - the client shows a loud notice: "`ann.example.org` now points to a different key (`V`'s fingerprint). Your friend `U` (fingerprint) is unchanged. If you didn't expect this, check with them another way.";
  - `send --to H` and `invite --to H` refuse while the change is unconfirmed;
  - confirming re-pins `H` to `V`. It makes `V` displayable under `H`; it doesn't make `V` a friend or carry anything over from `U`.
- The same applies to a `gh` handle whose numeric account id changed (R§6.3), and to every handle of a registrar whose log key changed (R§6.4.1).

### 9.3 Rotation, step by step

On a rotation from `U` to `V`, the owner's rotating client (§2.8, P3 "the plan") lists the owner's handles in the plan and:

- writes each handle's proof into `V`'s first document (new proofs, signed by `V`'s `ik`, in the same order);
- for `dns`, `web` and `gh`, prints exactly what to change: the TXT record value, the file's new contents, the gist file's new contents. The client can't change them itself;
- for `reg`, signs a `move` with `U`'s `ik` and an `accept` with `V`'s `ik`, and submits it before publishing the final version;
- leaves the proofs out of `U`'s final version. A rotation final version's proofs are never shown as handles anyway (R§5 rule 3).

Until the authority is updated, the handle verifies for **neither** `U` (its head is a final version) nor `V` (the authority still names `U`). Friends see "handle pending move" and no badge. This fails closed, and lasts only until the owner updates the record. When it is updated, friends who accepted the rotation follow automatically (R§9.2); others see a change of hands.

If rotations from `U` conflict (two statements, a contest), handles follow neither, as for every other carry-over.

## 10. Revocation, expiry and caching

### 10.1 How a binding ends

| Path | Who | How clients see it |
|---|---|---|
| The authority removes the counterpart (TXT removed, file deleted, gist deleted, domain lapsed) | the domain owner, the organisation, the GitHub account | definitive `not-found` on the next check; badge gone |
| The holder removes the proof from their document | the holder | gone on the next document refresh (every 10 min for friends, §2.5) |
| Registrar `release`, `expire`, `suspend` | the holder, or the registrar under its policy | on the next check; the holder's own client alerts on entries it didn't make |
| Rotation | the holder | R§9.3 |
| The client fails closed on the identity (§2.5, 60 days past `exp`) | nobody: the owner has been offline | badge gone with everything else |

An organisation that offboards someone deletes their record; the person loses the badge within one cache lifetime (at most 24 hours), and keeps their identity, their friends and every other handle.

### 10.2 Cache lifetimes

- **Positive answers:** the authority's TTL, clamped to **5 minutes – 24 hours**:
  - `dns`: the TXT RRset's TTL;
  - `web` and `reg`: the response's `Cache-Control: max-age` (default 1 hour if absent);
  - `gh`: 6 hours (GitHub's responses aren't a meaningful TTL, and the rate limit is tight);
  - a `reg` checkpoint older than 24 hours isn't fresh: the client fetches a newer one.
- **Negative answers** (`not-found`, `ambiguous`): 5 minutes, so a fixed record recovers quickly.
- **Transient failures:** the last verified state stays, marked "(not rechecked for <time>)", for a **72-hour grace** after its cache lifetime ends; then the badge goes. Someone who can block a client's lookups can keep a stale badge alive for at most 24 + 72 hours; they can't create one.
- **Before a decision:** `invite --to H`, `send --to H` to a handle not yet pinned, and every confirmation of a change of hands use a fresh lookup, never the cache.

### 10.3 Recheck schedule

- A client rechecks the primary handle of each friend and circle-mate when its cache lifetime ends, but at most once every **6 hours** per handle, with ±20 % random jitter, so lookups don't line up with when a contact comes online.
- Rechecks happen in the background, and only while the client is running.
- Non-primary handles are checked only on demand (`whois`).

## 11. Wire format and compatibility

### 11.1 What changes in protocol.md

- **§2.6 Proofs:** `kind` gains `"web"` and `"reg"` (claims and `loc` as in R§6.2 and R§6.4.3), and the forward-lookup file for `github` (R§6.3). `dns` and `github` proofs are unchanged.
- **New §2.9 Handles:** R§4 (syntax and normalisation), R§5 (binding), R§6 (resolution), R§7 (procedure), R§9 (pins and rotation), R§10 (lifetimes), as normative text; R§8 as display rules.
- **§2.1 and §7 "Names":** the fingerprint amendment in R§8.3.
- **§1 signed objects:** registers `p2p-handle-reg+jws` and `p2p-handle-accept+jws` (Phase 3). They are only ever stored in registrar logs and served by registrars; no relay or peer handles them.
- **Phase 4 only:** an optional identity-document field `hstaples` (R§12.2).

### 11.2 Why phases 1–3 need no two-step rollout

- An identity document's `proofs` is parsed as an array of at most 16 opaque strings (`identitydoc.ts`); no released client looks inside a proof while parsing the document. So a document carrying a `web` or `reg` proof is accepted by every client, including clients from before protocol 3.1.
- Proofs are checked only by `verifyProof` / `verifiedProofs`. A pre-RFC client sees an unknown `kind` as `malformed` in `verifyProof`, and `verifiedProofs` skips it. So an older client simply shows fewer proofs: it never shows a wrong one, and never rejects the identity.
- The off-network formats (TXT strings, the well-known JSON, `p2p-handle.json`, registrar answers) carry `v: 1`; unknown fields are ignored (3.1 must-ignore); an unknown `v` is `unsupported`: no badge, and not a negative answer either, so a newer format is never misread as a removal (and never verified by a client that can't read it).
- Nothing new is sent between peers, so no status cap and no `dinfo` entry is needed. A client advertises nothing about handle support.
- **No restricting fields:** nothing here narrows what an existing object allows, so nothing needs `crit`. If a later revision adds a field to a proof that restricts its meaning (an expiry, say), that field MUST be listed in `crit` (GOVERNANCE.md, "Compatibility rules").

### 11.3 Old forms

- An existing `github` proof keeps working as a `gh` handle in the reverse direction. Forward lookup needs `p2p-handle.json`; `p2p handle add github` writes it.
- An existing `dns` proof is a `dns` handle as is.
- Clients from before this RFC keep showing "✓ github: alice" and "✓ dns: example.org" exactly as today.

### 11.4 Test vectors

In the spec PR, under `packages/core/src/v3/testdata/`:

- `handles-normalise.json`: input → canonical form, or the refusal reason, covering NFKC folding, fullwidth input, UTS #46 edge cases (`ß`, ZWJ, bidi), punycode-looking local parts, IP literals, special-use suffixes and the 64-character limit;
- `handles-skeleton.json`: pairs with equal and unequal skeletons;
- `handles-binding.json`: documents, counterparts and the expected `status` (including `ambiguous`, a final rotation version, the other direction missing);
- Phase 3: `handles-reg-log.json`: entry chains with valid and invalid timings (premature `expire`, an unchained entry, a contested `move`).

## 12. Privacy

### 12.1 What lookups reveal, and to whom

| Party | Sees | When |
|---|---|---|
| The client's DNS resolver (often the ISP, or a public resolver) | `_p2p.<domain>` queries from this client's IP | every `dns` lookup and recheck |
| The domain's authoritative DNS servers | the query, usually from the resolver rather than the client | same |
| A `web` host | the client's IP, which handle, when | every `web` lookup and recheck |
| GitHub | the client's IP (or the configured token's account), which login, when | every `gh` lookup and recheck |
| A registrar | the client's IP, which handle, when; tile fetches don't say which handle | every `reg` lookup |
| Relays | nothing new: relays are never asked about handles; a hinted relay sees an ordinary public document fetch | — |

The interesting leak is the recheck: a host learns that someone at this IP has `ann` as a contact, and roughly how often they are online. A friend who controls their own `web` host learns each friend's IP that way.

### 12.2 Mitigations

- **A setting, `handles.verify`:** `friends` (default: rechecks for friends and circle-mates, on-demand otherwise), `ask` (only on explicit commands), or `off` (no lookups; no badges). Open circles (P2) admit strangers, so their members' handles are checked only on demand under any setting.
- **Jitter and batching** (R§10.3), so rechecks don't mark when a contact comes online.
- **Tor and DoH:** with the RFC 0001 Tor transport, every handle lookup goes through Tor; otherwise a client MAY use DNS over HTTPS.
- **No lookups from peer text** (R§7), so a peer can't plant a tracking host by mentioning it.
- **Registrar answers without the registrar (Phase 4, "staples"):** a `reg` answer is a set of signed, logged entries, so it can travel with the identity. An identity document MAY carry `"hstaples":{"<canonical handle>":<the R§6.4.3 log object>}` (informational, never `crit`). A client verifies a staple exactly like a fetched answer, against a checkpoint at most 24 hours old, and so needs no request to the registrar at all. This is the one new document field; pre-3.1 clients refuse unknown document fields, so it rolls out in two steps like `dinfo` (docs/compatibility.md).
- **Nothing new is published:** a handle is something the person chose to make public; the proof in their document is already public (§7).

## 13. Threat model

Assumptions: relays and peers may be hostile (as everywhere in the protocol); the user's own device and client are trusted; WebPKI and GitHub are trusted for what they assert, but can fail.

| Adversary | Can | Can't | Mitigation |
|---|---|---|---|
| **Hostile relay** | withhold a document, so a lookup is `unreachable`; serve a stale head | substitute another identity's document; make a handle resolve; add a badge | relays are never asked to resolve (R§7); documents are self-certifying; refreshing from every listed relay (§2.5) |
| **Hostile peer** | claim any handle in its own document; pick a lookalike handle or name; choose the host its own handle is served from | get a badge without the authority naming it; get a badge for a victim's handle; trigger lookups by mentioning one | two-way binding (R§5); skeleton warnings (R§8.4); no lookups from peer text (R§7); sanitizer strips fake badges (R§8.2) |
| **Hostile registrar** | refuse service; censor registrations; squat names before anyone else; `suspend` or (after 400 days' inactivity) `expire` a handle, then let someone else register it; serve a stale binding | bind a handle to a key that didn't sign a `register` or `move`; expire early without clients noticing; show different people different histories; rewrite the log | user-signed entries (R§6.4.2); timing checked from the log; witness cosignatures and consistency proofs (R§6.4.1); self-monitoring; any change of hands is loud to pinned clients (R§9.2); anyone can run another registrar |
| **DNS hijack** (registrar account takeover, expired domain, a compromised zone, an on-path resolver) | point `_p2p.<domain>` at its own userId, so that new lookups find the attacker | redirect existing friendships, trust or circles (they're bound to the userId); give the attacker the victim's badge on clients that pinned the victim | pins: a change of hands is loud (R§9.2); DNSSEC where available; for important handles, also publish a `gh` or `web` handle so that friends see two authorities agree |
| **WebPKI misissuance / web host compromise** | the same as a DNS hijack, for `web` handles | the same as above | the same; no redirects (R§6.2) |
| **GitHub account takeover** | publish a new `p2p-handle.json` and proof, so new lookups find the attacker | the same as above | pins; the numeric account id (R§6.3) catches login recycling |
| **GitHub login recycling** (the owner renames; someone else registers the old login) | publish a valid proof under the old login | keep the badge on pinned clients | the numeric id pin (R§6.3) makes it a change of hands |
| **Squatter** | register many names on a registrar | register unboundedly, or keep names forever without renewing | per-userId and per-IP limits, proof of work, reserved names, yearly renewal and inactivity expiry, a public dispute process (R§6.4.5) |
| **A stolen identity key** | remove the owner's proofs; add a proof for a handle the owner controls (it's already the owner's); sign a registrar `move` | complete a `move` the owner contests within 72 hours; change DNS, a web host or a GitHub account | the `move` hold and contest (R§6.4.2); the §2.5 alert on versions the owner didn't publish (proofs included); rotation (§2.8) |
| **An organisation, against its own people** | point an employee's `web`/`dns` handle at another key, or remove it | redirect existing friendships | a domain handle is exactly as trustworthy as the domain; the badge names the domain; pins make a change loud |
| **Lookalike handles** (`ann.examp1e.org`, `ann.example.org.evil.net`, punycode) | register them under their own authority | display as the real one: they show a different authority or a punycode A-label, and share a skeleton with the real one | R§4.3, R§4.4, R§8.2, R§8.4 |
| **SSRF and resolution abuse** (a handle whose host resolves to `127.0.0.1`, `169.254.169.254` or a LAN address; huge or slow answers) | nothing useful | make the client fetch a private address, follow redirects, or read more than 4 KiB | R§6.2 fetch rules; timeouts and size caps; lookups only on the user's command or the recheck schedule |

**What we are honest about:** handles are trust on first use. The first time someone looks up `ann.example.org`, they get whatever the domain says *then*. If the domain is hijacked at that moment, they find the attacker. Pins protect every later lookup, and the channel an invite travels over (§3.1, §7 "Identity") and the fingerprint in security prompts (R§8.3) remain the way to be sure on first contact. A handle tells you *who vouches* for a name, not that the person is who you think.

## 14. Alternatives considered

- **One project-run registry.** Simplest to build and to explain, and it would make one organisation the root of every name, which the constraints rule out. A community registrar here is one namespace among many, with its badge naming it.
- **Registrar-signed bindings (a CA model).** The registrar would sign "ann = U". That lets a hostile registrar re-point a name silently. With user-signed entries in a witnessed log, the registrar can only order statements users signed, plus a few logged, checkable policy actions.
- **Blockchain names (ENS, Namecoin).** They give global uniqueness without a registrar, but need a wallet, fees and a chain client or a trusted gateway (which would become the trusted party). Out of proportion for an agent messaging tool. An extension proof kind (§8.2) could add them later.
- **Email as a handle.** Verifying an email needs a server that sends mail (v2's hosted authority). Domain owners who want `ann@example.org` get exactly that from a `web` handle, without mail.
- **WebFinger (RFC 7033) for `user@host`.** A standard, and what the fediverse uses. But a WebFinger endpoint is usually owned by one application (a Mastodon server, say), so adding a link relation needs that application's support, and its JSON resource descriptor is larger than we need. A static file under `/.well-known/p2p/` works with any static host. We could additionally accept a WebFinger `rel` later; it's an open question (R§16).
- **DNS TXT and well-known for the same handle form** (the issue's first proposal: `ann.example.org` verifiable either way). Two counterparts for one handle means two attack surfaces and rules for when they disagree. Here each form has exactly one counterpart: `ann.example.org` is DNS, `ann@example.org` is HTTPS. This is the same split the AT Protocol makes between its DNS and HTTPS handle methods, from the other direction.
- **Keybase-style sigchains of social proofs.** Our identity document is already a signed hash chain carrying proofs; this RFC adds forward lookup and display rules on top, instead of a second chain.
- **A verifiable map (CONIKS, key transparency) for the registrar.** It would prove that the served binding is the latest, without monitoring. It is much more complex to build and run, and a stale answer here can only show an earlier holder, so monitoring is enough. It could replace the plain log later without changing user entries.
- **Unicode handles with mixed-script rules (UTS #39 restriction levels, PRECIS).** Better for people whose names aren't Latin, and much harder to make safe across every terminal and font. ASCII with punycode is the conservative start; Unicode display can be a later RFC.
- **Petnames only (status quo).** Safe, and doesn't scale beyond people you already know.

## 15. Rollout

Each phase is one PR (or a few), each lands its own spec text first, per GOVERNANCE.md step 4.

| Phase | What | New infrastructure | Wire |
|---|---|---|---|
| **0. Spec** | Accept this RFC; spec PR with §2.6, §2.9, §2.1/§7 amendments; test vectors (R§11.4) | none | none (text) |
| **1. Domain and GitHub handles** | Core: `normaliseHandle`, `skeleton`, `resolveHandle` with injected fetchers (as `ProofFetchers` today), the `web` proof kind, `owner.id` from the GitHub fetcher, SSRF-safe HTTPS fetcher. CLI: `p2p handle add/remove/list/check`, `p2p whois <handle>`, `--to <handle>` on `invite` and `send` (the invite's `aud` is bound to the resolved userId; the link still travels out of band). Display (R§8) in the CLI, the TUI, the Claude Code mod and the Codex bridge. Pins and change-of-hands notices (R§9). `handles.verify` setting | none | new proof kind `web` in documents (safe for every client, R§11.2) |
| **2. Rotation and polish** | Handles in the rotation plan (R§9.3); following on accepted rotations; lookalike warnings everywhere; DoH option; Tor routing of lookups once RFC 0001's transport ships | none | none |
| **3. Community registrar** | Reference registrar (a small open-source service: log in `tlog-tiles`, registration API, policy page); `reg` proof kind and entries; witness list; self-monitoring in clients. A separate, short policy RFC sets the reference registrar's defaults (R§6.4.5) if maintainers want them normative | a registrar, run by anyone; witnesses | `reg` proof kind; `p2p-handle-reg+jws`, `p2p-handle-accept+jws` (registrar logs only) |
| **4. Staples** | `hstaples` in identity documents (R§12.2): step 1 accepts it, step 2 sends it | none | one optional, non-critical document field; two-step rollout |

Phase 1 is useful on its own, needs no server, and covers the people most likely to want a handle first (anyone with a domain or a GitHub account). The registrar is deliberately after it, so the open questions about naming policy don't hold up the rest.

## 16. Open questions

For maintainers:

1. **Is the registrar part of launch?** This RFC says no: Phase 3, after domain and GitHub handles prove out. Should the project run a reference registrar instance at all, or only publish the software?
2. **Witness threshold.** `k = 1` at launch is weak against a registrar colluding with its one witness. Is `k = 2` from independent operators required before a registrar's badges are shown by default?
3. **Default `handles.verify`.** `friends` gives badges out of the box, and tells friends' hosts when you're online (within jitter). Is `ask` a better default for a privacy-first tool?
4. **Fingerprint in compact lists.** R§8.3 lets a verified handle replace the fingerprint in lists. Should a fingerprint stay visible, dimmed, for the first N days after a handle is first verified?
5. **WebFinger.** Accept a WebFinger `rel` as a second way to serve `web` handles, for fediverse servers?
6. **Reserved names.** Should the reserved list (R§6.4.5) be normative for every registrar, or each registrar's own policy?
7. **Unicode display.** Is a later RFC for Unicode display (with restriction levels) wanted, or is ASCII-only permanent?

Technical:

8. **GitHub forward lookup without the API.** The REST API's rate limit is the practical bottleneck. Is a public repository at a fixed path (`<login>/.p2p`, served by raw content hosts) a better forward location than a gist with a fixed file name?
9. **Public Suffix List freshness.** The badge uses eTLD+1; clients bundle a copy of the list. How often must it be refreshed, and what does a client show for a suffix it doesn't know (the full host, by default)?

## 17. References

- protocol.md §2.1 (addresses), §2.5 (identity document), §2.6 (proofs), §2.8 and P3 "Rotation", §5.5 (proof of work), §5.6 (documents on relays), §8.2 (trust providers).
- docs/compatibility.md (protocol 3.1, `crit`, two-step rollout); GOVERNANCE.md (RFC process).
- RFC 0001: metadata privacy and optional Tor transport (Tor routing of lookups).
- RFC 8615 (well-known URIs); RFC 7033 (WebFinger); RFC 8484 (DNS over HTTPS); RFC 4033–4035 (DNSSEC); RFC 1918, RFC 4193, RFC 6598 (non-public address ranges).
- Unicode UTS #46 (IDNA compatibility processing); UTS #39 (security mechanisms, confusables); UAX #15 (normalisation); RFC 5890–5891 (IDNA2008).
- RFC 6962 / RFC 9162 (Certificate Transparency); C2SP `tlog-tiles`, `signed-note`, `tlog-witness`, `tlog-checkpoint`.
- CONIKS (Melara et al., USENIX Security 2015); the AT Protocol handle specification (DNS TXT and HTTPS well-known methods); Keybase proofs.
- The Public Suffix List (publicsuffix.org).
