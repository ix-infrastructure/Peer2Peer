# Peer2Peer protocol v3 (draft 3)

An open, account-free protocol that lets AI agent sessions, and the people who run them, find each other, share what they are working on, and message each other end-to-end encrypted, through relays that anyone can run.

The never-enabled v2 draft is in [protocol-v2.md](protocol-v2.md), kept for the rules cited below. v3 keeps v2's cryptography, its envelope, its replay window, its friendship and unfriend rules, and its session rosters. It changes six things, each marked **[v3]** below:

| # | v2 | v3 |
|---|---|---|
| V1 | A hosted authority signs device certificates | The user's **own identity key** signs them; identities are self-certifying |
| V2 | userId = verified email | userId = **key fingerprint**; emails and handles are optional proofs |
| V3 | Workspace attestations from the hosted authority | **Circles**: membership lists signed by one owner and consented to by each member |
| V4 | The hosted authority's revocation list | A **hash-chained identity document** with a device allowlist |
| V5 | A hosted relay behind an account login | **Open relays**: device-signature auth, mailbox capabilities, 7-day store |
| V6 | Server-side presence | **`status` envelopes**, end-to-end encrypted |

It also adds **extension kinds** (`x:`), the seam through which extension features, such as Ix's, plug in (see [architecture.md](architecture.md)).

**Normative rule:** a conforming client implements this document and nothing from any extension. Every extension is optional, and a client without it still interoperates.

## 1. Primitives (unchanged from v2)
- **Algorithms:** Ed25519 for signatures (RFC 8032, verified strictly: `zip215: false`, small-order keys rejected); X25519 for key agreement; XChaCha20-Poly1305 for AEAD; HKDF-SHA256; SHA-256.
- **Encoding:** `b64u` is base64url without padding, decoded canonically. `b32` is RFC 4648 base32, lowercase, without padding.
- **Hashes:** `H(x)` is SHA-256. `jwsHash(j)` is `b64u(H(utf8(j)))` over the compact JWS bytes.
- **Signed objects:** every signed object is a compact JWS with `alg: "EdDSA"`, a mandatory `typ`, and a `kid`.
  - Verifiers check the received bytes and never re-serialize.
  - They check `typ` before any key lookup, and reject `crit`.
- **Size caps:** a non-envelope JWS is at most 16 KiB; an envelope at most 64 KiB.

## 2. Identity [v3: V1, V2, V4]

### 2.1 Identity key, userId and addresses
- **Identity key:** every user has one Ed25519 **identity key** (`ik`). It is generated on the user's first device. There is no account and no server registration.
- **userId:** `"p2p:" + b32(H(ik_pub))`. It is self-certifying, and it never contains `|`.
- **Display address:** `<name>@<fp>`.
  - `name` is self-chosen, matches `[a-z0-9._-]{1,32}`, and is **not unique**.
  - `fp` is the first **16** b32 characters of the fingerprint (80 bits), written in groups of four: `alice@k7f2-qx9a-3m4n-5p6q`.
  - Clients MUST show `fp` wherever they show `name`, and MUST compare full userIds for every decision.
  - Clients SHOULD let the user set a local **petname** for a userId, and show it in preference to `name`.

### 2.2 Key-holding devices
- **Default:** `ik` lives only on **key-holding devices**: the first device, plus any device the user explicitly promotes at link time (§2.4). Other linked devices hold their own device keys and certificates, but never `ik`.
- **Only key-holding devices can:** certify and renew devices; publish identity documents; sign proofs and rotations.
- **Why:** revoking an ordinary device (§2.5) therefore really cuts it off. A compromised key-holding device compromises the identity, and the remedy is rotation (§2.8).

### 2.3 Device certificate (`typ: "p2p-device+jws"`, `kid: "ik"`, signed by `ik`)
```
{ "iss":"<userId>", "ik":"<b64u ik_pub>", "did":"d_<b32(H(spk))[:26]>", "spk":"<b64u ed25519>", "kpk":"<b64u x25519>",
  "label":"<device label>"?, "iat":<s>, "exp":<s, ≤ iat+90d> }
```
- **[v3]** `did` is derived from `spk`, so nobody can claim another device's id (mailbox squatting, §5.2).
- **A certificate is valid when all of these hold:**
  1. `iss == "p2p:"+b32(H(ik))`;
  2. the JWS verifies under `ik`;
  3. `did` recomputes from `spk`;
  4. `spk`, `kpk` and `ik` pass the v2 small-order checks (C13);
  5. it is unexpired;
  6. `did` is listed in `devices` of the issuer's **current** identity document (§2.5). This makes the document an allowlist.
- **Renewal:** a key-holding device renews certificates automatically while online, and delivers them to the device by `sync`. Renewal keeps `did`, `spk` and `kpk`.

### 2.4 Linking a device
The existing device holds a secret; the new device proves it saw that secret.
1. **On the linked, key-holding device:** the user picks "link a device". The device generates a **link secret** `s` (16 random bytes) and shows `p2p-link:<b32(s)>@<relay host[:port][/path]>` **as a QR code or on screen**. The relay part is the canonical URL (§5.1) without `wss://`. The device then opens a pre-auth link mailbox (§5.7) on that relay, with link id `lid = b32(H("p2p/v3/link-id|" + s))[:26]`.
2. **The secret must travel only over a channel the user controls:** screen to camera, or typed by hand. Clients MUST tell the user never to paste it into a chat or show it on a screen share. It expires after 10 minutes and works once.
3. **On the new device:**
   - it generates `spk`, `kpk` and an ephemeral X25519 key `x`;
   - it puts the request `{did, spk, kpk, x, label, mac}` into link mailbox `lid` as frame `req`;
   - `mac = HMAC-SHA256(key = HKDF(s, info="p2p/v3/link-mac"), msg = lp(did) || lp(spk) || lp(kpk) || lp(x) || lp(label))`, where `lp(v)` is the 4-byte big-endian length of the UTF-8 bytes of `v` followed by those bytes;
   - it **displays its compare code**, `b32(H("p2p/v3/link-cmp|" + s + "|" + did))[:8]`.
4. **The linked device:**
   - verifies `mac`;
   - shows the new device's `label` and the **same compare code**, and the user confirms only if it matches what the new device shows. This stops anyone who glimpsed `s` from slipping in their own request.
   - If more than one valid request arrives, it aborts the link.
   - signs a certificate for it;
   - publishes a new identity document version that lists the new device;
   - seals `{cert, identity doc, ik_secret?}` to `x`, using the v2 envelope sealing with `info="p2p/v3/link"`. `ik_secret` is included only when the user chose to make the new device key-holding.
   - It delivers the sealed bundle to link mailbox `lid` as frame `resp`.

An eavesdropper who sees only the request learns nothing usable. Forging a request takes `s`.

### 2.5 Identity document (`typ: "p2p-identity+jws"`, `kid: "ik"`)
The user's public, signed, **hash-chained** profile. It is stored on and served by the user's relays (§5.6).
```
{ "iss":"<userId>", "ik":"<b64u>", "ver":<int>, "prev":"<jwsHash of version ver-1>" | null (ver 1 only),
  "name":"<name>", "relays":["wss://...", ...≤5], "devices":["<did>", ...≤10], "keyholders":["<did>", ...] (⊆ devices), "certs":["<device cert jws>", ...]?,
  "proofs":["<proof jws>", ...]?, "iat":<s>, "exp":<s, ≤ iat+30d> }
```
- **Extra fields:**
  - `"by":"<did>"` is the key-holding device that published this version. Every version carries it.
  - `"merge":"<jwsHash>"` appears only on merge versions, below.
  - **[protocol 3.1]** `"dinfo":{"<did>":{"caps":[...≤16],"client":"<version>"?}}` says what each listed device's client understands ("Forward compatibility", below). It is advisory: it decides what a sender may send, never what anyone may do. Keys must be listed devices; `caps` use the status caps' charset; `client` is at most 40 of `[A-Za-z0-9._+-]`.
- **Chain rule:**
  - each version has `ver = prev.ver + 1` and `prev = jwsHash(previous version)`;
  - clients keep the highest **chain-consistent** version per userId;
  - a client that misses versions fetches them (§5.6) before it accepts a later one.
- **Gaps that can't be filled:** when no listed relay still holds the missing versions, the client MAY jump to a head that verifies under the same `ik`, and warns its user ("history gap").
- **Publishers back-fill:** a device publishing to a relay whose head is older than the previous version first sends the missing versions.
- **Single writer:** among the devices in `keyholders`, the one with the lowest `did` does scheduled re-publishes. The others re-publish only when the head is within 3 days of `exp`.
  - Before publishing, a device fetches the head from every listed relay and builds on the newest.
- **Forks happen honestly** (two key-holding devices publishing at once), so a fork is **not** treated as compromise. A fork is two validly `ik`-signed versions with the same `(iss, ver)`. While the identity is forked:
  - a client keeps both branches;
  - it treats the **intersection** of their `devices` (and of their `keyholders`) as the allowlist, so a revocation in either branch applies;
  - otherwise it keeps working.
- **Resolving a fork:**
  - The scheduled writer (lowest `did` among key holders; any other key holder after the fork is 24 h old) publishes a **merge version**:
    - `ver = max(tip vers) + 1`;
    - `prev` = the tip with the higher `ver` (on a tie, the higher `jwsHash`);
    - `merge` = the other tip.
  - Merge versions are the one exception to `ver = prev.ver + 1`.
  - Clients accept a merge only when both parents verify **and** `merge.devices ⊆ (tip A.devices ∩ tip B.devices)`. A merge never adds or re-adds a device; adding one takes a later version.
  - Two different merges of the same tips are themselves a fork, resolved the same way.
- **Detecting compromise:** a stolen `ik` can simply extend the head, so forks prove nothing.
  - The real signal is a version the owner didn't make. Every key-holding device of the owner MUST alert its user when a version it didn't publish adds a device, a relay or a proof that none of the owner's devices added, judged by `by` and the owner's local log.
  - The remedy is rotation (§2.8).
- **Devices and revocation:**
  - `devices` is the allowlist of current devices.
  - **Revoking** a device means publishing the next version without it. From that point the device's certificate fails §2.3 rule 6.
  - A revoked `did` never returns, because re-linking makes new keys and so a new `did`.
- **Freshness [v3, replaces v2 L4]:**
  - A key-holding device re-publishes the document (as a new version) before `exp`.
  - Clients refresh the documents of their friends and circle-mates at least every 10 min while online, **from every relay the document lists**, and keep the highest chain-consistent version. That is what spreads revocations; `exp` only limits how long a stale view can survive.
  - **Past `exp`:** a client warns its user ("alice's key device hasn't been online for N days"), but keeps authorising.
  - **More than 60 days past `exp`:** it **fails closed** for that user, and stops authorising until it gets a fresh version.
  - **The user's own devices:** `sync` envelopes from the user's own devices (`from == to`) are exempt, so a user can always recover.
  - **Relays:** they keep serving and authenticating against an expired document, and senders keep sending to it. Expiry is only a receiver-side authorisation rule.
- **Liveness:** at `init`, clients MUST strongly prompt the user to make a backup (§2.7) or promote a second key-holding device. Without either, losing the first device ends the identity.

### 2.6 Proofs (`typ: "p2p-proof+jws"`, `kid: "ik"`)
A proof is an optional claim that this identity also controls some other name.
```
{ "iss":"<userId>", "kind":"github"|"dns"|"<ns>.<kind>", "claim":"<github handle | domain | …>", "loc":"<url of the counterpart>", "iat":<s> }
```
**Verifying a proof found in document `D`:** all of these must hold.
1. `proof.iss == D.iss`.
2. The proof verifies under `D.ik`.
3. The counterpart at `loc` contains **this exact proof JWS**:
   - for `github`: a public gist owned by account `claim`;
   - for `dns`: a TXT record `_p2p.<claim>` equal to `p2p-proof=<D.iss>`.
4. `loc` is the canonical location for that kind and claim: `https://gist.github.com/<claim>/...` for `github`, or the DNS name for `dns`.

**Display:** clients render only proofs they verified themselves, always prefixed with the kind: "✓ github: alice".

**Extension kinds:** proofs in an extension's namespace (`<ns>.<kind>`) are checked by trust providers (§8.2).

### 2.7 Backup (optional)
Backup is a 24-word BIP-39 mnemonic encoding the 32-byte `ik` seed.
- Restoring it makes the device key-holding. It then publishes the next identity document version, which normally revokes devices that were lost.
- Clients MUST offer a backup and MUST NOT require one.

### 2.8 Identity rotation
A rotation statement (`typ: "p2p-rotate+jws"`) is two JWS in one object, `{old, new}`: one signed by the old `ik`, one by the new `ik`. Each signs `{from:<old userId>, to:<new userId>, iat}`.
- Receivers carry a friendship over to the new id **only after asking their user**.
- More than one rotation from the same old id is shown to the user as a conflict, and neither is applied automatically.
- **Rotation re-keys every device:** new `spk` and `kpk`, and so a new `did`. Devices are never re-certified under a new `ik`, because relays bind a `did` to one `iss` (§5.2).
- The old identity publishes a final document version with `devices: []`. It carries the statement in its `rotation` field (P3), so it is self-certifying and served by the relays: a friend refreshing the old identity (§2.5) finds the move with no push.
- **Security:** someone who also holds the old `ik` can publish a competing rotation. Receivers then see a conflict and apply neither; people resolve it out of band, with petnames and proofs (§7). Rotation can't recover a circle whose owner identity is compromised: it needs a new `cid` (§3.3).

## 3. Social graph

### 3.1 Friends (v2 semantics, v3 ids)
- **Unchanged from v2:** `p2p-invite+jws`, `p2p-accept+jws`, `p2p-unfriend+jws`, the friendship certificate `{invite, accept}`, and every rule in v2 §"Objects signed by a device", C4 and H1.
  - The difference is that `iss`, `aud` and `peer` are v3 userIds, and signer certificates are §2.3 certificates.
- **[v3] New invite fields:**
  - `"ik"`, `"relays"` and `"doc"` (the inviter's identity document) let the invitee reach the inviter with no lookup.
  - `"cap"` is a **contact-only** capability (§5.3) for the invitee's first `contact` envelope.
- **Shareable codes:** `aud: "*"` stays the shareable-code form.
- **Link form:** an invite link is `p2p://invite/<b64u(invite jws)>`. The web form is `https://ix-infra.com/p2p/i#<same>`, with the fragment never sent to the server. Clients MUST still parse the deprecated web form `https://peer2peer.dev/i#<same>`, which earlier clients printed, and MUST NOT generate it.
- **Invites from strangers:** clients hold every invite that doesn't come from a friend or a co-member for the user to approve, and never act on it automatically.
- **Re-friending after an unfriend [draft 3 amendment]:** the H1 rule is unchanged: an unfriend ends every friendship of the pair whose invite was issued at or before it (`invite.iat <= unfriend.iat`, whole seconds, each by its signer's clock), so an invite issued before an unfriend can never resurrect the friendship. Clients therefore:
  - date a new invite **after** every unfriend they hold that it could meet: `iat = max(now, latest unfriend iat + 1)` over the unfriends between the inviter and `aud` (for `aud: "*"`, between the inviter and anyone). This covers a re-friend in the unfriend's own second and an unfriender whose clock runs ahead (by up to the 300 s skew). A client fetches what is queued for it before dating the invite, and refuses with a clock error when the floor is more than the skew ahead of its own clock;
  - **check before accepting:** an invitee that holds an unfriend of the pair dated at or after the invite refuses it before signing or sending anything, and says why (the inviter didn't yet hold that unfriend), so no friendship is recorded that every client then refuses. The inviter's next invite, made once it holds the unfriend, works. A single-use short code (P4) is spent by fetching it, so `p2p join` says the code is used up.

### 3.2 Blocks (local)
- A user can **block** a userId. A block is local and unsigned: the client rejects everything from that userId under every rule, including circles, and revokes that userId's capabilities (§5.3).
- An **unfriend** keeps v2 semantics: it ends standing through friendship only. Circle standing (§4.2) is unaffected, so to cut someone off completely, block them or leave the circle.

### 3.3 Circles [v3, V3]
A circle is a group whose consenting members see each other's sessions by default, the way v1/v2 workspaces did.

**One owner signs everything.** Each circle has exactly one **owner** (a userId). Every circle version is signed by the owner's **identity key** `ik`.
- Admins don't sign versions. They sign **proposals**, which the owner's client applies.
- Signing authority never spreads, so a removed admin has nothing to fork, and a copy of the circle can't be forged without the owner's `ik`. (This replaces the multi-signer design of revisions 1–3; see the review log.)

**Circle version** (`typ: "p2p-circle+jws"`, `kid: "ik"`, signed by the owner's `ik`):
```
{ "cid":"c_<b32(H(founder + "|" + nonce))[:26]>", "founder":"<userId>", "nonce":"<b64u 16B>",
  "ver":<int>, "prev":"<jwsHash of version ver-1>" | null, "owner":"<userId>", "ik":"<b64u owner ik_pub>",
  "name":"<display name>", "admins":["<userId>",...], "members":["<userId>",...],
  "transfer":"<p2p-circle-accept+jws>"?, "iat":<s> }
```

**A client accepts version `ver` only when all of these hold:**
1. `cid` recomputes from `founder` and `nonce`.
2. **Signer:** `owner == "p2p:"+b32(H(ik))`, and the JWS verifies under `ik`. The owner must also not be in the **fail-closed state of §2.5** (more than 60 days past `exp`) when the client accepts a new head.
3. **Chain:**
   - **for `ver == 1`:** `prev == null` and `owner == founder`;
   - **for `ver > 1`:** `prev == jwsHash(version ver-1)`, and the signer is the `owner` named in version `ver-1`. When that owner names a successor in this version (`owner` changed), it must carry `transfer`: a `p2p-circle-accept+jws` signed by the new owner's `ik` over `{cid, ver, prev}`. Ownership never moves without the new owner's consent to that exact state.

   Versions are never skipped. A client missing versions requests them (§4.3, `circle` kind) and accepts nothing newer until it has them.
4. Every admin is also in `members`, and so is the owner.

**History** is self-certifying. Every version is signed by an `ik` whose fingerprint is its `owner`, and versions are linked by `prev`. Old versions therefore stay checkable forever, with no certificate lookups.

**Concurrency:** only the owner's key-holding devices sign, and the single-writer rule (§2.5, the lowest `did` in `keyholders`) applies.
- **Replacing versions [review 5, high 1]:** a version that branches off the client's chain (a sibling of a version the client holds) can replace that branch only when its signer is the owner of the client's **current head**. So every version at or before the latest `transfer` the client holds is **final**, and a former owner can never rewrite anything.
- **Transfers win [review 6]:** a version carrying `transfer` is canonical against any sibling without one, whatever the hashes, and is never replaced by one. Two *different* transfer siblings are old-owner equivocation: the client **freezes** the circle at their parent and alerts its user. Since nothing can choose between them, members re-form the circle. The freeze applies **only** while the client's head is the transfers' parent, or while it is bootstrapping. A client already past a transfer ignores every sibling of it, transfer or not, whose signer isn't the owner of the client's current head, and only alerts. So a former owner can't freeze a circle it handed over.
- **Between the current owner's other siblings** (no transfer involved), every client chooses the one with the **lowest `jwsHash`** and switches to it, discarding versions built on the other. Every client reaches the same chain from the same set of versions.
- **Afterwards,** the owner's client re-applies anything the discarded branch changed, and prompts members whose join named a discarded version to re-sign it.

**Bootstrapping:**
- A new member accepts a circle only with its **full chain from version 1**, which can span several `circle` envelopes, checked under rules 1–4. There are no checkpoints in v3 [review 5, high 2]; a version is a few KiB, so even long chains are cheap.
- Circle invites show the **founder's**, the **owner's** and the inviter's addresses (§2.1), and say when ownership has changed hands.
- **Confirm before joining [review 6]:** the client asks for the head (`circle` `want`) from the owner named in the offered head **and** from at least one other listed member, other than the inviter, chosen from members the user already knows (friends or co-members), or otherwise at random from several, and waits up to 24 h for their answers. It refuses to join if any answer conflicts with the offered chain. If none arrives, it shows that it couldn't confirm and lets the user decide.
- **Answering someone who isn't a member yet [draft 3 amendment]:** a joiner who isn't a friend of the member it asks attaches an **answer cap** to its `want` (§5.3: issued by the joiner, `sub` = the member asked, `kinds: ["*"]`, living at most 24 h, the length of the wait above). The member answers with ordinary `circle` bundles presenting that cap, split across as many envelopes as the chain needs (§4.3 circle bundles), so a long history no longer has to fit one first-contact envelope: a 64 KiB `contact` envelope held about 6 versions of a 100-member circle. Each envelope of an answer carries `part: {id, i, n}` (one random `id` per answer, part `i` of `n`; at most 4096 parts), so the joiner knows when an answer is whole. The joiner counts an answer, from the owner or from any other confirmer, only once it holds every version from 1 up to the **offered head's** `ver` (a prefix confirms nothing) and every part of one answer that reached that far (its statements included); an unmarked answer counts once its versions reach the offered head. Until then it keeps listening, within its overall wait. A gap (`circle-gap` from bootstrapping) means the join is still waiting and never drops the pending join, except when every version up to the offered head's `ver` is there: then the offered head isn't on the chain (a fork), and that is a conflict. A later try asks again with `fromVer` at the first missing version, so a lost part or a member's spent budget resumes where it stopped.
  - **Abuse limits [review M1]:** a member answers **any** asker, members included, at most **10 times per rolling hour** (a member may leave and join again a few times; the byte budgets are what bound the cost), and sends one asker at most **4 MiB per rolling hour**; within the hour it doesn't send an asker versions it already sent them, except once (a lost part). All of one circle's members together share **16 MiB per rolling hour** of answers (an open circle admits up to 20 an hour, each with a per-asker budget of its own). Answers to non-members of the head also share a pool: **8 MiB per rolling hour** for askers whose `want` carries a valid **proof of work** `pow: {at, nonce}` (sha256(`"p2p/v3/want-pow|" + from + "|" + to + "|" + cid + "|" + fromVer + "|" + at + "|" + nonce`), where `to` is the member asked (its userId, the hash of its `ik`, so one proof is worth nothing at another member), with at least 18 leading zero bits, `at` within 10 minutes of the member's clock, each proof accepted once), and a separate **1 MiB per rolling hour** for those whose `want` carries none, so throwaway identities pay CPU for each share of the reserve (the reference client makes these configurable). **Open-circle joins can still be throttled:** an attacker willing to spend the CPU (and identities) can keep a member's reserve spent, so joiners wait for the next hour or fall to the small pool. The reserve and the work only raise the cost of doing so; they don't prevent it. Invite-only circles, and joins through a friend, aren't affected. The optional `link` (a version's jwsHash) grants nothing: such hashes are public (`prev`, join statements' `at`, any answer). Bytes are counted at their sealed size times the relays used, once per asker: the answer goes only to the device that asked (the `want`'s `fdid`). Every device of the member receives the `want`; the first in line answers at once: the lowest-sorting did among the key holders its identity document lists, then the other listed devices, lowest-sorting first, a choice every device makes alike. A device can't see what the others hold, so the order can't skip one that lacks the circle or is offline: the device at place r answers r × 2 minutes later (configurable) unless one of the member's devices has answered that asker about that circle since. Each device tells the others in `sync` what it answered (bytes, pool and the proof of work spent: every budget and pool is shared, so a fallback never multiplies them) and what it refused (the others don't answer that either). An answer that reached no relay isn't reported. A device dates a want it holds back by the want's envelope `ts`, drops it after 30 minutes, checks blocks and the circle's policy before holding it back, holds at most 4 per asker, and re-checks everything (the proof's window included) when it answers. The limits are checked before an answer is built or an identity document fetched. An answer larger than what is left is cut to whole versions, and a cut answer always stops short of the head, so the answer that reaches the head (and so counts as whole) carries the statements; the joiner asks again later from the first missing version, so a chain larger than one hour's budget still gets through, over several hours. The answer cap is the joiner's consent to receive the answer; it reaches only the joiner's own mailboxes, for a day, and is revoked with the joiner's other caps if they block the member.
  - **Without an answer cap** (a client from before this amendment), the member answers only when the head and chain fit one `contact` envelope (§4.3), which the relay's first-contact limits (§5.4) bound; otherwise it doesn't answer. A member from before this amendment rejects a `want` carrying `cap` as malformed (plaintexts are strict), so it answers a non-friend joiner only once updated; a friend's `want` carries no cap and works with either.
  - **Why the full chain, and not a shorter proof:** a stranger could check the head against the owner's key and the chain of `transfer`s back to the founder, but that isn't enough to be a member. Standing (below) requires each member's join `at` to be an ancestor of the held version, so the joiner needs the history back to the oldest `at`; sibling resolution, transfer finality and equivocation freezes (above) are judged over the held chain; and rule 3 accepts nothing newer until every earlier version is held. Skipping versions is a checkpoint, which review 5 (high 2) rejected. Whole chains therefore stay, sent in chunks, and the abuse limits above bound what they cost the member.

**Membership statement** (`typ: "p2p-join+jws"`, signed by a member's device):
```
{ "iss":"<member userId>", "cid":"<cid>", "n":<int, per (member, cid), strictly increasing>,
  "op":"join"|"leave", "at":"<jwsHash of the circle version the member accepted>" (join only),
  "cap":"<p2p-cap+jws, sub:"*", kinds:["*"]>" (join only), "iat":<s> }
```
- **Ordering:**
  - For each `(member, cid)`, the statement with the highest `n` is current. On a tie, `leave` wins, then the lowest `jwsHash`.
  - The member's devices keep `n` in step through `sync`. Each new statement uses one more than the highest `n` any of them has seen.
- **The join's `cap`** lets every co-member reach the joining member (§5.3), so a circle of any size needs no per-pair cap exchange.
- **Signer validity:** a membership statement needs a signer valid (§2.3 rules 1–6) when the client receives it. Clients keep statements they already accepted.
  - A member therefore re-signs its current statement, with `n+1` and a fresh `cap`, when its signing device is revoked, its certificate is within 7 days of `exp`, or its cap is within 30 days of `exp`.

**Proposals** (`typ: "p2p-circle-op+jws"`, signed by an admin's device; the signer must be valid when received):
```
{ "iss":"<admin userId>", "cid":"<cid>", "base":<ver the admin saw>, "op":"add"|"remove"|"promote"|"demote"|"rename",
  "target":"<userId>"? , "name":"<new name>"?, "nonce":"<b64u 16B>", "iat":<s> }
```
- **Delivery:** an admin sends proposals to the owner in `circle` envelopes.
- **Applying:** the owner's client applies a proposal automatically, in arrival order, only when **all** of these hold:
  - `iss` is an admin in the **current head**;
  - its `iat` is within the last 30 days, and its `nonce` is not in the owner's applied set. That set is kept with the circle, synced across the owner's devices, and pruned of nonces older than 30 days;
  - no version after `base` changed the same `target`. Otherwise it is stale: it is dropped, and the owner's client tells the proposing admin so it can re-propose.

  It then publishes the next version.
  - It skips a proposal whose effect already holds, for example removing someone who isn't a member.
  - It refuses `promote`, `demote` and `remove` aimed at the owner.
- **The owner** may also set a policy to hold proposals for approval.
- **While the owner is offline,** proposals wait in the owner's relay mailboxes (up to 7 days). An admin re-sends a proposal older than that only while the head doesn't yet reflect it.
- **Owner loss:** if the owner is gone for good, or in the §2.5 fail-closed state, the circle can no longer change, so removals stop working. Clients show members a "circle frozen: owner unavailable" notice. Members should leave and re-form it. An owner SHOULD hand ownership over (`transfer`) before going away, and a circle whose owner is a service identity SHOULD keep a recovery path for that identity.
- **Owner compromise:** the owner's key-holding devices MUST alert on any circle version of theirs that they didn't publish. A circle whose owner identity is compromised can't be recovered by rotation, and must be re-created under a new `cid`.
- **Admin powers:** any admin's proposals can promote, demote or remove other admins. Owners who need tighter control set the hold-for-approval policy.

**Membership counts only with consent.** A user `u` **stands** in circle `cid` on a client when:
- `u ∈ members` of the client's held version, **and**
- the client holds `u`'s current membership statement, and it is a `join`, **and**
- that join's `at` is an ancestor of, or equal to, the client's held version.

**The viewer's own standing** additionally requires the viewer to have **joined** the circle on this device: a local, explicit user action that signs the viewer's own join statement.
- A circle the viewer never joined grants nobody anything on that viewer's device, whoever sent it (review C1).
- **Joining:**
  1. The owner or an admin invites someone by sending them the head version, with its chain. That goes in a `circle` envelope when the inviter holds a cap for them, and otherwise in a `contact` envelope (§4.3).
  2. The invite is held for the user's approval, like any first contact.
  3. On approval, the client signs a join statement and sends it to the owner and the admins.
- **Adding:** the owner adds the user to `members`, directly or on an admin's `add` proposal.

**Removal:**
- The owner removes a member by publishing the next version without them, directly or on a proposal.
- **Members stop counting someone the moment they hold the version that dropped them.**
- **Leaving:** a member leaves by signing a `leave` statement with a higher `n`, and sending it to **every** member.
  - Members honour it at once.
  - The owner then drops the member from `members`.

**Distribution and freshness:**
- The owner sends each new version, along with the membership statements it holds, to every member, **and to all of the owner's own devices**, as `circle` envelopes.
- The owner's client re-sends the head **every 24 h**. A member client whose head is more than 72 h older than the newest head it has heard of requests the missing versions from any member.

### 3.4 Session rosters (v2, with `org` → `circle`)
- **Unchanged:** `p2p-roster+jws` with `ver`, `sid`, `parts` and the per-`(own, sid)` rules.
- **[v3]** `vis` is `"circle"` or `"private"`. The field `"org"` is replaced by `"circle":"<cid>"`.

## 4. Envelopes

### 4.1 Format (v2 §"Message envelope", unchanged except as marked)
Outer fields: `v, from, fdid, fcert, to, tdid, own, sid, seq, ts, n, epk, ct, kind`.
- **[v3]** `v` is `3`.
- **Receiver checks before opening:**
  - `fcert` is valid under §2.3;
  - `fcert.iss == from`;
  - `fcert.did == fdid ==` the JWS header `kid`;
  - the envelope signature verifies under `fcert.spk`;
  - `from` is not forked, not expired and not blocked.
- **[v3]** The sealing, the AAD form (prefix `"p2p/v3|"`), the KDF info (`"p2p/v3/msg|"+fdid+"|"+tdid`) and the 64 KiB cap are as in v2.

### 4.2 Authorisation (v2's two-sided `mayExchange`, with circles in place of workspaces)
A user satisfies the rules for a roster `R` on this client when one of these holds:
- **(a)** `user == R.iss`;
- **(b)** `R.vis == "circle"`, and **both** `R.iss` and `user` **stand** in `R.circle` (§3.3);
- **(c)** `user ∈ R.parts`, **and** either:
  - there is a live friendship between `user` and `R.iss`, **or**
  - both `R.iss` and `user` stand in `R.circle`.

**Both sides must pass:** the sender (`from`) **and** the viewer, checked independently.
- The viewer's side uses only the viewer's own stored friendships and circles it has **joined** (v2 H1, review C1).
- Blocks (§3.2) override every rule.
- **[v3]** Rule (b) needs the owner to stand in the circle. That replaces v2's D9 owner-attestation machinery.

### 4.3 Kinds
| kind | sid | authorised by | plaintext |
|---|---|---|---|
| `msg` | session | §4.2 against `(own, sid)` | `{text, roster?, rcpt?}` (`rcpt`: below, "Delivery receipts") |
| `roster` | session | §4.2 | `{roster}` |
| `idle` | session | §4.2 | `{reason}` |
| **`status`** [v3, V6] | session | §4.2 | `{status: {state:"busy"\|"idle", label, repo?, branch?, mode?, summary?, files?, summaryAt?, caps?, agents?}}` (unknown status fields are ignored, below) |
| `sync` | any | `from == to` only | user-defined: friendships, circles, joins, caps, renewed certs, identity doc |
| `unfriend` | session | `from` signed it, recipient is `peer` | `{text: <unfriend jws>}` |
| `contact` | `~contact` | a valid `fcert` chain; `own == from` | exactly one of: an invite, accept or unfriend JWS; a `p2p-cap+jws` grant from a stored friend (§5.3); a circle invite `{circle:<head version jws>}`, held for approval; a rotated friend's `{rotation, invite}` (P3), held for approval |
| **`circle`** [v3] | `~circle` | a valid `fcert` chain; `own == from`; the sender is a friend, or stands in the circle, or is a member of it; otherwise held for approval as a circle invite | `{circles:[<circle jws>,...], joins:[<membership statement jws>,...], rotation?, part?}` (`rotation`: P3; `part`: §3.3, draft 3 amendment) **or** `{want:{cid, fromVer}, cap?:<answer cap jws>, link?:<jwsHash>, pow?:{at, nonce}}` (`cap`, `link`, `pow`: §3.3, draft 3 amendment) |
| **`receipt`** [draft 3 amendment] | `~receipt` | a valid `fcert` chain; `own == from`; the recipient asked `from` for it (below) | `{receipt: {id, outcome}}` |
| **`x:<ns>.<type>`** [v3] | session | §4.2 | `{ext: {v:<int>, body:<any JSON>}, fallback:"<≤200 chars, plain text>", state?: {ttl}}` (`state`: a state kind, below) |

**Circle bundles:** a chain longer than one envelope allows is split across several `circle` envelopes. The reference client keeps each part's plaintext under 30 KiB of UTF-8 JSON (sealing and two layers of base64 make an envelope about 16/9 of it). An answer to a non-member's `want` is split the same way and sent with the `want`'s answer cap (§3.3).

**Statuses:**
- `status`, `idle` and `roster` describe the session itself, so only its owner sends them (`from == own`); a receiver rejects one from anyone else as `not-session-owner`. A participant writing into someone else's session (§4.2) may send `msg` and extension event kinds only.
- A sender emits `status` when its state changes, and otherwise every 60 s while running.
- A session counts as **live** for 150 s after the **`ts`** of its last `status`, not after arrival. A relay that holds a status back cannot make a dead session look live.

**Status forward compatibility [draft 3 amendment].** So that later revisions can add status fields without a version bump:
- A receiver MUST ignore a top-level field of the `status` object that it doesn't know. It drops the field: it never stores it, shows it, passes it to a model or an extension, or acts on it.
- A receiver still validates every field it knows exactly as defined here, and rejects the envelope as `malformed` when one fails (`state`, `label`, `repo`, `branch`, `mode`, `summary`, `files`, `summaryAt`, `caps`, `agents`). An unknown field never excuses a malformed known one.
- ~~Only the `status` object is tolerant. The outer plaintext, every other kind's plaintext, signatures, ids, kinds and sizes stay strict.~~ Superseded by "Forward compatibility" (protocol 3.1, below): every plaintext ignores unknown fields unless they are critical; signatures, ids, sizes and every known field's checks stay strict. The envelope size cap (64 KiB) still bounds the whole status, unknown fields included.
- A sender SHOULD keep a status plaintext under 8 KiB.
- Clients written before this amendment reject a status carrying any field outside the original list, `caps` included. Nothing was public before it, so it amends draft 3 rather than bumping `v`. A sender adds a field defined after this amendment only for a recipient whose live status advertises the matching cap.
- **Rollout in two steps.** Step 1 (this amendment's first release) shipped the tolerant parser and `caps` validation, and did not send `caps` by default: a status then still carried only the original fields, so clients from before the amendment kept accepting it. **Step 2 (the `agents` release, footprint P1) sends `caps` by default.** A user whose peers still run a client from before the amendment opts out (in `packages/p2p`: `P2P_STATUS_CAPS=0`, or `"statusCaps": false` in `config.json`): the status then carries only the original fields again, and a caller's caps and agents are left out, never an error. A missing `caps` now means an older client, or one that opted out.

**Status caps [draft 3 amendment].** `caps` lists what the sending client understands, so a peer can ask "does this session understand X" before sending it something newer:
- At most 16 distinct entries. Each is at most 40 characters, matches `^(x:)?[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$`, and names a feature and its version, for example `agents.v1`. An extension's caps carry its kind's `x:` prefix, for example `x:ix.footprint.v1`. A list that breaks any of these rules makes the status `malformed`.
- `status.tolerant.v1` means "I implement the forward-compatibility rules above". Every client that sends `caps` includes it.
- A status without `caps` understands nothing optional (an older client, or, during step 1, one that hasn't opted in).
- A cap is a hint about what to send, never authorisation. It isn't free text: the charset above leaves nothing to sanitize. It holds only for the status it came in, and a later status replaces it.
- A receiver tests for a cap only in a real list (an array), never by substring.

**Status agents [draft 3 amendment, cap `agents.v1`].** `agents` lists the session's subagents (the agent loops it spawned), so peers see who in it is working on what:
- At most 8 entries, each `{id, parent?, type, task, state, files?, wt?, branch?, at}`, and no other field:
  - `id`: a session-local ordinal, `^a[1-9][0-9]{0,3}$`, unique in the list. It is never the agent runtime's own id.
  - `parent`: the `id` of the listed agent that spawned it; absent when the session's main loop did. Nesting is flattened to depth 2: a parent has no `parent` itself (so there are no cycles). A sender attaches a deeper agent to its depth-1 ancestor.
  - `type`: 1-32 characters of `[A-Za-z0-9:_ .-]`, no leading or trailing space (`Explore`, `general-purpose`, `teammate`, a plugin's agent).
  - `task`: 1-80 code points, already one sanitized line (the sanitizer below leaves it unchanged). It is the spawn's short description, never the agent's prompt.
  - `state`: `running`, `waiting`, `idle`, `done` or `failed`.
  - `files`: at most 10 distinct paths under the `files` rule below, at most 200 characters each, most recent first. They are relative to the agent's own checkout: its worktree's root when `wt`, else the repository's.
  - `wt`: `true` when the agent's edits are in its own git worktree, not yet on the session's `branch`. `branch`: that worktree's git branch, 1-128 characters of `[A-Za-z0-9._/-]`, no `..`, no leading `-` or `/`, no trailing `/`.
  - `at`: its last activity, a non-negative integer in ms.
- A list that breaks any of these rules makes the status `malformed`, as for every known field. A client re-validates a stored list before showing it, and shows none of a list that fails.
- **Who gets it.** A status goes to a user, one plaintext for all their devices. A sender includes `agents` for a recipient only when every live session of that user it knows of advertises `agents.v1` (and there is at least one). Everyone else gets the status without `agents`, and the agents at work (not `done` or `failed`) counted in `summary` instead: `<summary> (+N agents)`, still within the summary's 280 characters. A device of that user with no live session is not known, and is assumed to be like the user's live ones.
- **Sender limits.** At most 60 distinct paths across `files` and every agent's `files`; the plaintext stays under 8 KiB, the oldest agents dropped first; a `done` or `failed` agent is dropped after 10 minutes, and before any other when trimming.
- **Privacy.** `agents` has exactly the session's audience (§4.2), and a client that stops sharing the session's status stops sharing it too. It never carries prompts, transcripts, final answers, the runtime's agent ids, worktree directory names that embed them, or absolute paths.
- `type`, `task`, `files` and `branch` are peer-supplied text: shown through the sanitizer below and framed as peer data, like `summary`.

**Delivery receipts [draft 3 amendment, cap `receipts.v1`].** "Delivered" used to mean only that a relay took the message; a session could say it to someone whose client held the message for approval, or put it in a session nobody was watching. A receipt says what became of it:
- **Asking.** A sender includes `rcpt` in a `msg` only when the target session is live (§4.3, 150 s) and that live status advertises `receipts.v1` (a client from before this amendment rejects `msg` with any other field: the plaintext stays strict, and the whole message would be lost). A stale status never decides it: a message to a session that isn't live, or a copy kept to send later (no relay is reachable, or the recipient's relays didn't take it), carries no `rcpt`. A copy that already went out on a connection whose answer never came is resent as sealed (the recipient's replay window drops a second copy), so it keeps the `rcpt` it was sealed with. `rcpt` is a random id of 8-32 characters of `[A-Za-z0-9_-]`, fresh for each message. The sending device remembers which user it sent the id to and which of its sessions sent it, for 7 days.
- **Outcomes.** `shown` (handed to the session's model), `held` (waiting for its user's approval), `declined` and `expired` (a held message), and `ended`: the target session had ended and the message was offered to its user's other sessions. A message has at most three receipts (`held`, then one of the others); nothing follows a final outcome (`shown`, `declined`, `expired`, `ended`), and each outcome is sent once.
- **Sending.** The receipt is a `receipt` envelope, `own == from`, sid `~receipt`, plaintext exactly `{receipt: {id, outcome}}`: no text, no session id, no other field. It goes only to the authenticated sender of the message (`from`), and only to the device that sent it (`fdid`). It never asks for a receipt itself, so receipts can't loop.
- **Privacy.** A session shared with nobody (private) sends no receipts, since one would tell the sender it exists. The copy of a message for an ended session says only `ended`, whatever the session holding it did, never which session has it. Receipts are a presence signal (the cap tells everyone who sees the status that the session reports outcomes, and `shown` says when a model got the message), so a client says so where it turns them on by default. A user may turn receipts off; their sessions then stop advertising `receipts.v1` too, so senders see what an older client looks like and can't tell the two apart.
- **Limits.** A client sends at most 30 receipts a minute to one user. Past 120 a minute in all, a user gets only a fair share (120 divided among the users receipted that minute, this one included), and 240 a minute is the ceiling. Past a limit it sends none (an outcome is never queued for later).
- **Receiving.** A receipt is accepted only from the user the id was sent to, for an id this device sent, at most three per id and each outcome once; anything else is dropped without an event. It reaches the session that sent the message, and is shown or given to a model only as data about that message.
- **Older clients.** No receipt can mean an older client, receipts off, or one that was lost. A client says "no receipt yet" and, when the session didn't advertise `receipts.v1`, that their client may be older; it never treats a missing receipt as "not delivered".

**Forward compatibility [draft 3 amendment, protocol 3.1; docs/compatibility.md].** So that a peer one version ahead can never make a message fail:
- **Unknown fields are ignored** in every plaintext (§4.3), in the outer envelope (§4.1), and in every signed object (identity documents, device certificates, caps, invites, accepts, unfriends, rosters, proofs, circle versions, transfers, membership statements, proposals, rotation statements). A receiver copies the fields it knows and drops the rest: it never stores, shows or acts on one, and every known field keeps all of its checks. Signatures and `jwsHash` are over the object as received, unknown fields included.
- **Critical fields.** Any of those may carry `crit`: 1-16 distinct names of fields it carries (never `crit` itself). A receiver that doesn't understand a listed field refuses the object (`unsupported-critical`); a malformed `crit` is `malformed`. An issuer MUST list in `crit` any field that restricts what the object allows (a narrower cap, an extra condition), so an older receiver never reads it as allowing more. Relays apply the same rule to what they parse (envelopes, certificates, caps).
- **Exclusive discriminators.** A `contact` plaintext carries exactly one of `text`, `circle`, `rotation`; a `circle` plaintext is a `want` or a bundle, never both.
- **Unknown kinds.** An envelope whose `kind` this version doesn't know, shaped `^[a-z][a-z0-9_-]{0,31}$`, is verified like any other (the sender's identity known and unexpired, `fcert`, the signature, blocks, the replay claim), opened, never parsed or authorised for anything, and recorded in the replay window. Only when the sender is the user's own device, a friend (a friendship not ended by an unfriend) or someone who stands in a circle with them does the client keep the sender's device certificate, log it (once per sender and kind an hour) and tell its user, once per (sender, kind) a day and at most 3 times a day per sender, as data ("<peer> sent a <kind> this version doesn't understand: update to see it"). From anyone else it is recorded in the replay window and nothing more. Any other kind is `malformed`. A client sends a kind defined after 3.0 only to a peer that advertises it.
- **What a client understands** is advertised per session in the status `caps` (now also `proto.3.<minor>`; never the exact client version, which would help single a device out) and per device in the identity document's `dinfo` (§2.5, where `client` may carry it). A sender sends anything defined after protocol 3.0 only on positive evidence: the target session's live status, the device's `dinfo` entry or latest status, or every live session of a user (for what goes to a user as one plaintext). Clients from before 3.1 refuse every unknown field, so `dinfo` rolls out in two steps (docs/compatibility.md).
- **Relays** list in `/.well-known/p2p-relay.json` their `protocolMinor`, the `frames` they answer and their `features` (`identity.lenient`, `envelope.lenient`, `invite-mailbox`, `link-mailbox`, `members`), beside `access` and `attention` for members-only relays. Frames ignore fields a relay doesn't know; a client checks a feature before relying on one. A relay that lists none is protocol 3.0 with the baseline frames; a client asks it for nothing newer.

**Peer-supplied text is untrusted [v3, review M5].** That covers every string that comes from a peer, including any added later:
- `summary`, `repo`, `branch`, `label`, `mode`, `files`, every `agents` string, `fallback`, circle `name`, device `label`, identity `name`, proof `claim`, and trust-provider `label`.

Before showing such text to a person or a model, a client passes it through **one** sanitizer:
- strip C0, C1, Cf and U+2028/9;
- collapse whitespace;
- remove `<` and `>`;
- cap the length.

`files` entries must also be relative paths with no empty, `.` or `..` segments, no leading `/` or `\`, and no drive letter; otherwise they are dropped.

Clients that put peer text into a model's context MUST frame it as **data from a named peer**, never as instructions.

**Extension kinds:**
- A receiver without the extension shows the sanitized `fallback`, prefixed with the sender's address. It never interprets `body`.
- An extension MUST ask its user before acting on received content outside the conversation, for example writing a received note into a local graph.

**Extension state kinds [draft 3 amendment, cap `xstate.v1`; footprint P2].** An extension may declare some of its kinds as *state*: a session's latest value of something (an Ix footprint), not an event.
- **Marker.** A state kind's plaintext carries `state: {ttl}`, where `ttl` is an integer of 10-3600 seconds (default 600). `state` may hold nothing else; a malformed one makes the envelope `malformed`. Clients from before this amendment reject any plaintext carrying `state` (the extension plaintext was always strict), so such a client never shows one.
- **Who gets it.** The session's owner sends it to the session's status audience (§4.2, exactly as `status`; never to a single target), and to its own other devices. A sender sends a state kind to a user only when every live session of that user it knows of advertises `xstate.v1` (and there is at least one), and then only to the devices those live sessions run on: a device with no live session, or one running an older client, never gets one.
- **Caps.** A client that keeps state kinds advertises `xstate.v1`. A client with an extension that declares a state kind also advertises that kind's cap, `<kind>.v<n>` (for example `x:ix.footprint.v1`), so a sender can tell who will interpret the body as well as keep it. A kind whose cap would be over 40 characters can't be declared as state.
- **Receiving.** A receiver accepts a state kind only from the session's owner (`from == own`). It keeps the latest per `(sender, session, kind)` by envelope `ts`, replacing what it held, after the extension (when installed) validated the body; without the extension it keeps the sanitized `fallback` only, and never interprets `body`. A state kind is **never** an event: it is not logged, not printed in an event stream, never toasted, and never shown to or delivered to a model. A value is dropped once its session is no longer live (§4.3, 150 s), or `ttl` seconds after the earlier of its `ts` and its arrival.
- **Unknown to the extension.** When a loaded extension owns the kind's namespace but doesn't declare the kind as state, the receiver keeps only the `fallback` (no body) and never hands the value to the extension as state.
- **Limits.** `{v, body}` is at most 16 KiB. A sender updates one kind of one session at most once every 5 s. A receiver drops a value less than 4 s (the 5 s minus 1 s of clock slack) after the previous one it kept for that key, and accepts at most 120 values a minute for one (sender, session), so a user with many sessions isn't throttled by their own count, and at most 240 a minute from one sender across all their sessions (session ids are free to make up). It keeps at most 128 per-session rate windows per sender, the newest. It keeps at most 8 kinds per session; per sender, at most 64 values and 64 KiB, where each value is charged at least 1 KiB plus its `fallback`, kind, sid and a fixed overhead (their oldest values go first); and at most 512 values in all. Over that global cap, the sender holding the most values gives up their oldest first: values are never evicted across senders by age, so one sender can't push out everyone else's state.
- **Showing.** A client lists at most a bounded summary of a session's state (kind, times, size and the sanitized `fallback`), never a body. That summary is plain CLI output (`p2p ls`): anything that can run the CLI sees it, a model's shell tool included, so a client never puts it into a model's context itself, and the `fallback` is peer text like any other (sanitized, never instructions). An extension reads its own kinds' kept bodies.

### 4.4 Replay (v2 D6 + D7, with a longer window)
- **[v3]** `ts` must be within `[now - 7d - 10 min, now + 10 min]`, matching the relays' 7-day store.
- **Unchanged from v2:** the per-`(fdid, own, sid)` 512-entry sliding seq window and the atomic check-and-record.
- **Record what was applied:** a client SHOULD record an envelope in its window only once the envelope's effects are written, and acknowledge it to the relay only after that. Otherwise a crash in between turns the relay's redelivery into a "replayed" drop, and the message is lost. The reference client claims the envelope atomically with the check, so a concurrent copy (another relay, another process) waits instead of being applied twice. It then records the envelope after applying it. A claim whose holder died is taken over by the redelivery. Holders on the same machine are judged by liveness only, never by age, so a slow holder keeps its claim; a claim from another host sharing the home is taken over after 2 minutes. An attempt that fails for a transient reason (a lock timeout, a full disk, the command closing, a dropped or unreachable network) gives the claim up unrecorded and doesn't acknowledge, so the redelivery is applied. Any other failure is final at once and spends the seq. Every claim counts as an attempt: after 3, the envelope is recorded as given up (acknowledged, never applied), so a poison envelope can't come back for the relay's whole retention. Holders are told apart by pid and process start time, so a reused pid doesn't stand in for a dead holder. A copy whose claim is held by a live holder waits without taking the store's lock (a read of the stored claims); only the locked claim takes or takes over a claim. Because a relay sends an envelope once per connection, a long-lived client (the watch) that waited on another holder's claim handles that envelope again itself after a backoff, while its connection lasts. A command that exits with an attempt still running gives that claim back without counting it as a failed attempt, but such abandoned attempts have a cap of their own (10), so an envelope whose handling always outlives a short command is given up too; the abandoned attempt sends nothing more.
- **Offline sessions and an offline sender (reference client):** relays store ciphertext for 7 days, so a client need not refuse a message because the target session isn't live. The reference client sends to a session of the recipient last seen (by its status) within 24 hours, to that user's devices only and with the same caps; when no relay takes a message it keeps the sealed envelope and resends the same bytes later, never re-sealing it, so the replay window drops any copy a relay did store. Both expire 7 days after sealing, matching the 7-day limit on an envelope's age. On the receiving side, a message for a session of that device that isn't running anymore is also surfaced, as data, to the user's other sessions.
- **Retention:** clients MUST keep each replay window for at least 7d10m after the last envelope it admitted, even after the session ends.
- **Nonce LRU:** the per-device nonce LRU is defence in depth, as in v2.

## 5. Relays [v3, V5]

### 5.1 Role
A relay is a dumb store-and-forward server:
- It sees **only** the outer envelope fields, capability tokens, identity documents and connection metadata.
- It never decides who may talk to whom beyond enforcing capabilities and rate limits.
- Anyone may run one. Clients MUST work with any conforming relay.

**Canonical relay URL:**
- scheme `wss`;
- host lowercased, as an IDNA A-label;
- port omitted when it is 443;
- path exactly as configured, without a trailing `/` (default `/v3`);
- no query or fragment.

Every relay URL in an identity document, a capability or a `hello` is in canonical form.

### 5.2 Connection and authentication
Transport: `wss://<host>/v3` (JSON text frames, one object per frame, at most 96 KiB).
1. **Challenge:** the relay sends `{"t":"hello","relay":"<its canonical URL>","nonce":"<b64u 32B>","pow":<bits for first contact, 0..24>,"limits":{...}}`.
2. **The client MUST check `hello.relay` against the canonical form of the URL it actually dialled**, and close the connection if they differ (review H5). It then replies:
   `{"t":"auth","cert":"<device cert jws>","sig":"<b64u Ed25519_spk("p2p/v3/relay-auth|"+hello.relay+"|"+nonce)>"}`.
3. **Relay checks:**
   - the certificate is valid under §2.3 rules 1–5;
   - rule 6 as well, when the relay holds the issuer's identity document;
   - `sig` verifies.
4. **Result:** the relay binds the connection to the mailbox **`(cert.iss, cert.did)`** and replies `{"t":"ok"}`.
   - Because `did` is derived from `spk`, only the holder of that key can claim it.
   - A relay rejects a second `iss` for a `did` it already knows.

### 5.3 Mailbox capabilities (`typ: "p2p-cap+jws"`, `kid` = a recipient device id; carries that device's cert as `cert`)
A capability is the recipient's signed permission for one sender to reach their mailboxes.
```
{ "iss":"<recipient userId>", "sub":"<sender userId>" | "*", "cert":"<signer device cert>", "capid":"<b64u 16B>",
  "relays":["<canonical relay URL>", ...], "kinds":["*"] | ["contact"],
  "iat":<s>, "exp":<s, ≤ iat+90d>, "uses":<int>? }
```
**Who gets one:**
- **Friends:** a cap with `sub` = the friend and `kinds: ["*"]`, issued in both directions.
  - The invitee's cap travels in the accept.
  - The inviter's cap goes back in a `contact` grant (§4.3) as soon as the accept is recorded.
  - Renewed caps travel in `sync`, or in `contact` grants.
- **Circle co-members [review M3]:** the member's join statement carries one cap with `sub: "*"` and `kinds: ["*"]`, which names no circle, so a relay can't map it to one. It reaches co-members only inside end-to-end encrypted `circle` bundles.
  - A relay can't check circle membership, so anyone who obtained the cap could use it to *reach* the member. But they still fail §4.2 on the member's device, so the cost is spam, not access.
  - A member who sees abuse revokes the cap and re-joins with a fresh one (higher `n`).
- **Other `sub: "*"` caps** MUST have `kinds: ["contact"]` (shareable invites), and SHOULD have `uses`.
- **Answer caps [draft 3 amendment]:** a joiner's `want` to a member who isn't its friend carries a cap for that member: `sub` = the member, `kinds: ["*"]`, `exp − iat ≤ 24 h`. The member presents it to deliver its (chunked) answer (§3.3), and uses it for nothing else. Clients reject an answer cap that is `sub: "*"`, another kind, or longer-lived. Relays need no change: to them it is any cap naming its sender.

**Relay checks when a cap is presented** (§5.4):
- `relays` includes this relay;
- `kinds` allows `env.kind`;
- `uses` is enforced per relay.

**Revoking:** on unfriend, block, or a co-member's removal, the issuer sends `{"t":"revoke","capid"}` to **every** relay the cap names. Only an authenticated device of `cap.iss` may revoke it.

**What a relay learns:** a cap reveals `iss` and `sub`, so the relay learns which userIds may reach which mailboxes. That is the friend and co-member graph in pseudonymous form (§7).

### 5.4 Sending and receiving
- **Send:** `{"t":"send","id":"<client msg id>","to":"<recipient userId>","tdid":"<did>","env":"<envelope jws>","cap":"<cap jws>"?,"pow":"<b64u nonce>"?}`
- **The relay checks, in order:**
  1. the envelope parses, is at most 64 KiB, and `env.to == to` and `env.tdid == tdid`;
  2. `fcert` verifies (§2.3 rules 1–5), and the envelope signature verifies under `fcert.spk`, so the sender fields can't be spoofed;
  3. **with `cap`:**
     - the cap is valid, and its `cert` verifies;
     - `cap.iss == to`;
     - `cap.sub ∈ {env.from, "*"}`;
     - `relays`, `kinds` and `uses` allow this send;
     - it is unexpired and not revoked;
  4. **without `cap`:** only `kind == "contact"`. It is rate-limited per sender userId, per (sender, recipient) pair and per source IP (defaults: 60/h, 3/h and 120/h), and it needs `pow` when `hello.pow > 0`. The pow condition is `H(env_bytes || pow)` having that many leading zero bits.
- **Reply:** `{"t":"sent","id"}` or `{"t":"error","id","code"}`.
  - Codes: `undeliverable` (any capability or mailbox failure, one code so nothing leaks), `rate-limited`, `too-large`, `bad-envelope`.
  - **A cap-less `contact` to a mailbox the relay doesn't know is answered `sent` and silently dropped.** That way it doesn't reveal whether the mailbox exists.
- **Store:** the relay stores the envelope for mailbox `(to, tdid)` until it is acked, or for 7 days.
- **Delivery:** `{"t":"env","rid":"<relay id>","env":"<jws>"}`, in arrival order, while the mailbox has a live connection.
  - The client acks with `{"t":"ack","rids":[...]}`, and the relay deletes acked envelopes.
  - On reconnect, everything un-acked is delivered again. The receiver's replay window drops duplicates.
  - **Caught up:** once everything stored for the mailbox when it authenticated has been sent on the connection, the relay sends `{"t":"caught-up"}`, once per connection (with an empty mailbox, right after `ok`). A short-lived client stops listening for queued envelopes there, once it has handled the ones delivered before it (envelopes arriving live after `caught-up` don't hold it), instead of waiting out a quiet period. It only ends a wait early, so it carries no authority: a relay that sends it too soon can do no more than one that withholds envelopes. Clients ignore frame types they don't know, and fall back to a quiet period with a relay that never sends it.
- **Default limits:** a mailbox holds at most 10,000 envelopes and 64 MiB, dropping the oldest first. Senders get 120 sends/min per `env.from`.
  - A relay advertises its limits in `hello.limits`, and MAY be stricter.

### 5.5 Proof-of-work and spam
- Cheap identities make the per-sender limits weak. The real defences are:
  - capabilities;
  - pair limits;
  - clients holding strangers' invites for approval (§3.1).
- A relay MAY raise `pow` under load.

### 5.6 Identity documents on relays
- **Publish:** `{"t":"identity","doc":"<p2p-identity+jws>"}`, from an authenticated device of `doc.iss`. The relay accepts it when its `prev` (and, for a merge, its `merge`) is a version the relay holds, or when the relay holds none. It keeps every branch, serves the highest `ver` as the head, keeps every version for 90 days, and keeps heads indefinitely.
- **Fetch:**
  - `GET https://<host>/v3/identity/<userId>` is public and returns the head;
  - `GET .../identity/<userId>/tips` returns every branch tip the relay holds (more than one only during a fork);
  - `GET .../identity/<userId>/chain?to=<jwsHash>&n=<≤64>` walks back from a given version along `prev`, and along `merge` for merge versions, so a client can fill gaps on any branch.
  - Clients fetch every tip from every listed relay, so a revocation on any branch is seen.
- **Scope:** a relay serves only documents whose `relays` list includes its canonical URL.

### 5.7 Pre-auth link mailboxes (device linking, §2.4)
- **Opening:** `{"t":"link-open","lid":"<26 b32 chars>"}` comes from an authenticated device, and opens a mailbox keyed by `lid`. It lives 10 minutes and holds one `req` slot (up to 4 entries) and one `resp` slot, each entry at most 16 KiB.
- **Unauthenticated access:** `{"t":"link-put","lid","slot":"req"|"resp","data"}` and `{"t":"link-get","lid","slot"}` are accepted **without auth**, and the relay rate-limits them per IP.
  - A `req` put appends while the slot has room.
  - A `resp` put is accepted only on the connection that opened the mailbox.
  - A `get` returns every entry in its slot, in arrival order.
- **Client guidance:** a client without a device certificate connects, does one `link-*` operation, and closes. It polls by reconnecting, within the relay's advertised `limits` (`unauthTimeoutSec` and `linkOpsPerIpPerMinute`), never by holding a connection open.
- **Security:** only holders of the link secret know `lid`, and the contents are MAC'ed and sealed (§2.4).
- **Invite mailboxes** (short-code invites) are specified in P4.

### 5.8 Multiple relays
- **Listing:** a user lists 1–5 relays in the identity document. There is no built-in or public relay: the user (or their invite) supplies them, and 2 or more are recommended so one relay going down is harmless.
- **Receiving:** receivers stay connected to all of their relays.
- **Sending:** senders send each envelope to **every** relay listed for the recipient, up to 3. The replay window makes this idempotent.
- **What one relay can do:** a relay that is down or dishonest can drop or delay copies. It cannot read, forge or redirect them, and it cannot drain another relay's mailbox (§5.2).
- **Delivery failure:** clients surface "delivered via 0 relays" as a failure.

## 6. Clients
- **Local state:** a client keeps the following in a local store with mode 0700:
  - identity and device keys, in the OS keychain where one exists, otherwise in a 0600 file;
  - friendships, unfriends, blocks, circles and joins, rosters, capabilities issued and held, cached identity documents, replay windows.

  v2's `FileTrustStore` lock and atomic-write rules (C7, C14) apply.
- **Agent sessions:**
  - A session id is generated per agent run.
  - **Project boundaries (reference client, local):** a session's roster follows its *project* (docs/concepts.md "Projects"): the git repository, or folder, it works in. Each project's policy is the user's local decision (shared with circles and named friends, or private), and a project with no policy is private. A session is bound to every project it has worked in until it ends, and its roster is never wider than the intersection of their policies: a private one means `vis:"private"` with no participants. A roster the user never set explicitly follows that policy: the client signs the next roster version to match before its next status (a project's roster names one circle, the user's default circle when the project shares it, else the first, plus as participants the friends the project shares and the friends among the members of its other circles). One set explicitly is cut down to the policy when the policy narrows, and can't be widened past it. The decision and the write are made under one lock against the roster as stored, so a concurrent explicit change is never undone, and a version is never reused or lowered.
  - The same client refuses to send `msg` and extension kinds from a session to anyone outside its projects' audience, and drops `msg` and extension kinds into one of its own sessions from anyone outside it, whatever roster the message presents. A message for no session (into the sender's own session) is held only in a local session whose projects reach the sender. None of this changes the wire: an older client sees a private roster, or no status at all.
  - **`bound` (cap `projects.v1`):** a `msg` or extension-kind plaintext between one user's own sessions may carry `bound`, `"private"` or `{circles: [cid…], people: [userId…]}` (at most 32 each): who the sending session may reach. It is sent marked critical (`crit: ["bound"]`), only from a session with a ceiling, and only to the user's own devices (one whose session's status doesn't advertise `projects.v1` isn't sent to). The receiving client binds the target session to it: sticky, intersected with its own projects. Peers never get it.
  - **Same-device sessions (reference client, local):** a `msg` or extension kind from one session to another session of the same user *on the same device* is an ordinary envelope sealed to that device (`from == to`, `fdid == tdid`), sent through the user's relays with the device's own cap, and verified on receipt like any other (signature, replay window, `bound`). Nothing on the wire changes. The client sends one only to a session named explicitly (`[ref]` or `/sid`): a bare target naming the user never picks a session on the sending device. It never sends one to the sending session itself. A receipt (above) for such a message goes back to the same device. Before sending, the client records locally, by the envelope's `(sid, seq)`, which session sent it and whether that was the person's own terminal session; the receive side, on the same device, uses the record to name the sending session and to apply the hold rule (an own agent session's message is held where a peer's would be). The record is never sent: another device of the same user can't tell a person's message from an agent's, and treats it as an agent's. Carrying that on the wire needs an RFC.
  - Before project boundaries, rosters defaulted to the user's default circle; the default circle now only picks what an invite joins.
  - The Claude Code mod and the Codex bridge are clients like any other.
- **Trust (local, reference client):** a client that holds peers' messages for an agent that approves its own tool calls (docs/clients.md, "the hold rule") may let the user trust senders: by full userId, or a circle, whose members count as its verified state has them when a message arrives: anyone its owner or admins add (a removed member, or a circle the user left, ends their trust). An open circle (P2) admits anyone who asks, so it is never trusted, including a trusted circle that becomes open. Trust is the user's local decision, never sent to anyone, never added by the agent, and never covers a blocked user. It only skips the hold: a trusted sender's text is still peer data (§4.3).

## 7. Security notes
- **What relays see:**
  - who may reach whom, through capabilities (`iss`/`sub`), even before any message;
  - who sends to whom, at userId and device level;
  - envelope sizes and timing;
  - every envelope's plaintext outer fields (§4.1): `from`, `fdid`, `to`, `tdid`, `own`, `sid`, `seq`, `ts` and `kind`. So a relay can tell the kinds apart (`msg`, `status`, `roster`, `idle`, `sync`, `unfriend`, `contact`, `circle` and extension kinds such as `x:ix.note`), and sees the target session id and the sequence and timestamp counters. These fields are bound into the AEAD's associated data, so they can't be altered, but they aren't hidden. A relay reads `kind` itself (§5.4: only `contact` is accepted without a cap);
  - identity documents, which are public by design.

  Content (message text, status contents including labels, summaries and files), circle names and membership (except a circle's chain on a members-only relay that follows it, §5: name, owner, admins, members), rosters and friendship certificates are end-to-end encrypted. Metadata-private routing is out of scope for v3 as written; the accepted privacy phase is in [Roadmap and open questions](#roadmap-and-open-questions).
- **Names:** `name` is unauthenticated. Addresses show 80 bits of fingerprint (§2.1); petnames and verified proofs are how people tell lookalikes apart.
- **Identity:** a userId is self-certifying. Whether it *is the person you think* rests on the invite channel, petnames and proofs.
- **Device loss:**
  - **An ordinary device** (not key-holding) is cut off by publishing the next document version without it.
  - **A key-holding device** that is stolen while unlocked compromises the identity. The owner's own key-holding devices alert on versions they didn't publish (§2.5), and the remedy is rotation (§2.8). The thief can publish a rotation of its own, which friends see as a conflict (P3, "Rotation").
- **Circles:**
  - Membership needs the member's consent (a join statement), and a client honours only circles its user joined. Nobody can be enrolled into someone else's circle to reach them.
  - Only the owner's identity key signs circle versions, and the versions are hash-chained. Admins only propose. A copy of a circle can't be forged, and a removed admin has nothing to fork.

## 8. Extensions
### 8.1 Namespaces
Extension kinds and proofs use short namespaces, such as `ix` for Ix.
- New namespaces are registered in this file by PR.
- An extension MUST define a `fallback` text for each of its kinds, and MUST NOT change any rule in §2–§5.
- An extension declares which of its kinds are state kinds (§4.3 "Extension state kinds"); a state kind is never sent as an ordinary (event) kind, and an event kind never carries `state`.

### 8.2 Trust providers
A trust provider is a pluggable checker of proof kinds in its namespace. It returns `{ok, label, expiresAt?}`.
- **Labels:** clients render a label **prefixed with the provider's namespace**, for example `✓ example: alice@example.com (Example Corp)`, so no provider can imitate another's badge.
- **Limits:** a provider can only add a badge. It can never grant authorisation, link devices, or change circle membership.

### 8.3 Registered
| ns | kinds | proof kinds | spec |
|---|---|---|---|
| `ix` | `x:ix.note`, `x:ix.subgraph`, `x:ix.impact`; state kind `x:ix.footprint` (cap `x:ix.footprint.v1`, ttl 600 s) | — | [`packages/ext-ix/SPEC.md`](../packages/ext-ix/SPEC.md) (v1, Phase 6) |

## Draft 3 additions (Phase 2)
Two small social features, implemented in `@peer2peer/core/v3`. Neither changes any rule above: they add optional fields that older clients ignore.

### P1. Profiles
An identity document (§2.5) MAY carry `"profile":{"bio":"…","avatar":"…","links":["https://…",…]}`, every field optional:
- `bio`: at most 280 characters.
- `avatar`: an `https:` URL (at most 512 characters), or a `data:image/(png|jpeg|webp|gif);base64,…` URI of at most **4 KiB**. SVG is not allowed. The cap keeps the document within the §1 16 KiB limit with its certificates, and lets it still ride inside a 16 KiB invite (§3.1).
- `links`: at most 5 `https:` URLs, each at most 512 characters.

Every profile field is peer text: clients pass it through the §4.3 sanitizer before showing it. Avatars are untrusted: a client MUST NOT fetch a remote avatar without the user's opt-in (a fetch tells the host that someone looked at this profile, and when). A profile is not a proof: it never changes how an identity is displayed (§2.1) or verified.

### P2. Open communities
A circle version (§3.3) MAY carry `"policy":"invite"|"open"`. Absent means `invite`.
- **Invite links:** `p2p://circle/<b64u(head version jws)>`, with the web form `https://ix-infra.com/p2p/c#<same>` (the fragment never reaches the server). Clients MUST still parse the deprecated web form `https://peer2peer.dev/c#<same>` and MUST NOT generate it. A link only lets the holder find the circle; joining still needs the full chain (§3.3 bootstrap) and confirmation.
- **Joining an open circle:** the joiner signs an ordinary join statement (`op: "join"`, `at` naming a version it holds, its join `cap`) and sends it to the owner in a `circle` envelope. This is the joiner's consent by construction.
- **The owner's client applies it automatically** under `policy: "open"` when the statement verifies (signer valid on receipt, §3.3), is the joiner's current statement, names a version on the owner's chain, and the joiner is not blocked. It then publishes the next version adding the joiner, exactly as for an `add`.
- **Limits:** the owner's client auto-accepts at most **20 joins per rolling hour** (configurable). Beyond that, and for anyone the owner removed, the join is held for the owner's approval. Under `invite`, every join request is held.
- **Removed stays removed:** clients record a member as *removed* when the owner publishes a version that drops it while its current statement is a `join` (it didn't leave), and clear the record only when a version lists it again. A join from a removed identity is always held for the owner's approval, whatever the identity signed in between: a `leave` followed by a fresh `join` doesn't reset it. The reference client holds every former member's join this way, whether it left or was removed: a client can't tell a voluntary leave from a removal followed by a leave the removed member signed afterwards (the removed member gets the version that drops it, and can hand it, with its leave, to a device of the owner that hasn't applied it yet). Telling them apart needs owner-signed removal markers in versions: future work.
- **Short-lived join caps [pre-release review M4]:** every member of an open circle can be reached with any co-member's join cap (`sub: "*"`, `kinds: ["*"]`, §5.3), and auto-accepted strangers collect them. So in a `policy: "open"` circle:
  - a join cap lives **at most 14 days** (`exp − iat ≤ 14 d`). Clients reject (do not apply) a join statement in an open circle whose cap lives longer, and the owner's client doesn't auto-accept it;
  - members re-sign their join (`n+1`, a fresh cap) before the cap lapses (3 days before, by default), and at once when a circle they hold becomes open with a longer cap;
  - **clients never redistribute a join statement whose cap doesn't fit the circle's policy** [review N5]. Every `circle` bundle a client sends (the owner's re-sends, answers to `want`, invites) withholds such statements; a member whose statement is withheld is reachable again once it re-signs;
  - a stranger who **leaves voluntarily** isn't removed, so nothing is re-keyed: the caps it collected keep working at the relays until they expire, at most 14 days;
  - **when the owner removes anyone** from an open circle, every member's client re-signs its join with a fresh cap and revokes the old `capid` at every relay it names (`{"t":"revoke","capid"}`, §5.3). A removed or departed stranger's copies of the old caps then stop working at the relays.
- **The owner may switch back to `invite` at any time** by publishing a version with `policy: "invite"`.
- **Nothing else changes:** only the owner signs versions, the chain, transfer and finality rules are as above, and membership counts only with consent (§3.3) and authorisation is exactly §4.2. An open circle lets strangers *become members*, so circle-wide rosters (`vis: "circle"`) in an open circle are visible to anyone the owner auto-accepts; clients SHOULD say so when a session is shared to an open circle.

### P3. Readings chosen while implementing
These are the places where the text above needed an interpretation; `@peer2peer/core/v3` implements the reading given.
- **Ed25519 signatures (§1).** "Verified strictly" also rejects a signature whose `R` has a torsion component (`R = rB + T`, `T` of small order). A cofactored verifier (noble's `zip215: false`) would accept such a signature where a cofactorless one (OpenSSL) rejects it. With `R` and the key both torsion-free, the two equations agree, so every verifier gives the same answer for the same bytes, whatever the message size. Honest signers never produce a torsioned `R`. `@peer2peer/core` and the relay both enforce this.
- **Transfer versions (§3.3 rules 2–3).** `owner`/`ik` name the successor (`owner == H(ik)` always holds); the JWS is signed by the previous owner, so it verifies under version `ver-1`'s `ik`; `transfer` verifies under this version's `ik`. Every version is checkable from its parent alone. A `p2p-circle-accept+jws` payload is `{iss, ik, cid, ver, prev, iat}`.
- **"Final" (§3.3).** A sibling can replace the client's branch only when its signer is the current head's owner **and** the version it would replace comes after the latest transfer on the client's chain.
- **`from` "not forked" (§4.1)** is read as §2.5 says: a forked sender is not rejected; rule 6 runs against the intersection of its branches. "Not expired" means not in the 60-day fail-closed state.
- **A stranger's first `contact` (§4.1), narrowed after the pre-release review (M1).** When the receiver holds no document for the sender, a `contact` envelope is opened after rules 1–5, and rule 6 is applied against the identity document the carried invite or accept brings (`doc`), before anything is returned. Every other kind needs the sender's document first. That bundled document is only **provisional**:
  - it must verify and must not be in the §2.5 fail-closed state (more than 60 days past `exp`);
  - it **never becomes the client's stored view of that identity** [pre-release re-review N1]. It goes only into a separate, bounded provisional cache (256 entries, 24 h) that no authorisation path reads: not rule 6 for any other envelope, not stored friendships, not circle freshness. It only says which relays to fetch the real head from. So `provisional` is recomputed from the stored identities every time, and a replayed envelope stays provisional;
  - before acting on the user's approval (accepting the invite, adopting the accept), the client fetches the head from every relay the document lists, adds what the relays return to the stored chain, and re-verifies the object against the stored chain alone. A bundled document may be stale: it can still list a device revoked since, and this step is what catches it. That refresh, never the bundled document, is the only way the identity enters the store. Gaps are filled by walking back with the §5.6 `chain?to=` request on every listed relay. A version the chain rules reject (a revoked device returning, a merge adding a device) is never adopted, by any route. If the newest version still doesn't connect: when the client held no history, or only unanchored history, it gap-jumps to it (§2.5, with the "history gap" warning), so a stale version 1 can't pin the identity; over anchored or forked history it fails closed, and a jump is only ever the user's explicit choice [pre-release review N6/N7]. A gap jump drops the jumped-over history but keeps a **revocation denylist** [pre-release review R1]: for each held branch, the devices its ancestors listed and its tip no longer lists. A revoked `did` never returns (§2.5), so those stay out of the allowlist for good devices added later are unaffected, and the view isn't left `forked`. Refreshes treat relay responses as hostile [R2, review S1]: each listed relay is asked separately, with its own timeout (a relay that doesn't answer is skipped), and its answer is capped on its own, keeping its highest-`ver` signature-valid documents first (8 tips, 64 per chain page), so one slow or hostile relay can't push out another's revoking head. Each document's signature and `iss == H(ik)` (and the held `ik`) are checked before any chain work. The refresh's local work is bounded, never counting network time; hitting the bound keeps what was placed, reports the refresh as incomplete, and an incomplete refresh never counts for approval. The signature-valid tips an incomplete refresh saw above the stored head are kept as **pending heads**. While any is still above the head, the view trusts only the devices and key holders every one of them lists, so a version committed on the way can't trust what a newer one already revoked. This only narrows the view and is never a permanent denial:
    - each pending head is dropped once the head reaches its `ver`;
    - all of them are dropped by the next complete refresh that a majority of the relays the held document lists answered (a minority's, or relays added from elsewhere such as a link's unverified document, only drop those its head reached; freshness is counted the same way);
    - one issued in the future or past its `exp` is ignored;
    - a client never applies them to its own identity, in any read: a version only the identity key signed can't stop the owner's devices from editing, publishing or rotating it, or from accepting each other's `sync` (the §2.8 rotation sync among them);
    - only the ones that narrow are kept: walking them highest `ver` first, one is kept if it leaves out a device or key holder no higher kept one already leaves out (the highest is always kept). None that narrows is ever evicted, however many versions a relay sends.

    A gap left at the end of the chain walk is a real one only when it is **settled**: every relay was asked for the missing version and none sent it (checked or not). A relay that doesn't answer counts as not holding it, except one that had given the walk valid documents. Relays not yet asked for a gap (typically those whose share ran out) are asked once more at the end, and their answer is only hashed, with no signature checks; these probes cover at most 8 gaps, taken in turns by the relay that sent them. Any gap not settled makes the refresh incomplete, so what was placed is committed and the next refresh goes on [#35, #67].

    An answer longer than the request asked for is dropped unread. A settled gap is a real one, handled as above, so a relay that answers with junk can't keep a refresh incomplete. One residual is accepted: a hostile relay can replay genuine versions it got elsewhere, use up its share, then not answer the probe, and so keep a real gap (one no relay can fill) "incomplete" rather than a broken chain. That costs liveness only (nothing unconnected is committed, and an incomplete refresh never counts for approval), and a relay that never gave a valid version can't do it [#65 review, #67].

    A client far behind still catches up [#67]. The verified versions where an incomplete refresh's walk stopped are kept locally as **walk anchors** (at most 16, taken in turns by the relay that sent them, lowest `ver` first, with the relays that sent them), and the next refresh walks on from them instead of from the tips again, so every refresh makes progress whatever the distance. Walk anchors only say where to ask next: they are never part of the view, are re-verified when loaded, are placed under the chain rules like any fetched version, and are cleared by a complete refresh. The walk asks only for frontier gaps (the missing version isn't one the walk already holds). When the relays asked have nothing new for one gap, the next one is tried, so a dead side branch doesn't stop the newest version's history from filling. The walk's requests are shared in turns between the relays that supplied the gaps, so a relay sending many versions whose gaps nobody can fill (forgeries signed with the identity key) can't use up the request cap before another relay's gap is asked for. An entry hashing to a version a gap misses is checked even after its relay's checking share is spent: junk never hashes to one, and each is checked at most once per refresh, so junk sorted ahead of a genuine missing version can't keep the gap "cut short". None of this lets a relay spend another relay's share or allowance.

    A refresh also reports which relays sent a version left on a **dead** gap: one whose missing version every relay was asked for (and answered, the sender too) and none had, checked or merely hashed. It never names a relay for what the request cap, the work budget or a spent share left unasked, so an honest relay whose genuine gap simply wasn't reached isn't named. Each relay is named only for what it sent itself. The refresh also lists every version it left unconnected above the head, with the relays that sent it [#67]. The owner's client uses both for its own identity, below;
  - a friendship whose verification leaned on a bundled document can't be recorded until it has been re-verified this way. In `@peer2peer/core/v3`, that proof is an in-memory brand on the re-verification's result: `reverifyFriendshipForApproval` and `recordFriendshipV3` must run in the same process, on the same object, within 10 minutes. It doesn't survive serialization;
  - stored friendships are re-verified only against stored chains, never against a document bundled in their invite or accept.
- **The owner's own refresh before publishing (§2.5, §2.8) [#67].** Before publishing the next version of its own identity, a client refreshes it from every listed relay and refuses to build on a head it couldn't confirm, so that it doesn't fork its own chain by building on a stale head. Someone holding the identity key (a thief) and one listed relay can serve versions signed with that key, at a far higher `ver`, that don't connect to the owner's history. Such a refresh then never completes. Without a rule for it, the owner couldn't use either remedy: removing that relay is itself an edit, and rotation's final version is a publish. So:
  - for an edit that removes relays, the refresh is retried over the listed relays the edit keeps; for a rotation step, over the listed relays other than those named for dead gaps (above). The edit or rotation goes ahead only if that refresh is complete and its head is not below any version the first refresh left unconnected, unless every relay that sent that version is set aside. Only for named relays does the client warn that someone else may hold the identity key;
  - so a relay that merely lags can't "confirm" a stale head while another relay serves a newer version, and a forger can't get an honest relay set aside. If the forging relay isn't named (it stays silent, or its gaps weren't all asked), rotation refuses; removing that relay still works, then rotate. If a named forging relay is the only one serving a genuine newer version, that version is attributed only to it, and the rotation fallback proceeds on the head the honest relays confirm: a version only the forger serves can't be relied on;
  - any other edit still refuses while such a relay is listed, and names it, with the remedy (remove it, or rotate);
  - nothing is set aside when no listed relay would be left.

  Why this keeps the protections: a newer version another of the owner's key holders published went to every listed relay, so the relays kept still serve it, and a complete refresh over them connects to it and builds on it (or, far behind, ends incomplete and the edit is refused until a later try catches up). Leaving a relay out is what the strict refresh already allows when that relay doesn't answer. The relays left out are chosen by the user (the ones being removed) or by each relay's own answers: one relay can't get another left out. The version published is the next `ver` on the head the kept relays confirm, so a relay left out can't make it lower or make it fork from anything else. The forged versions are reported to the user rather than waited for: that is the §2.5 compromise signal, and rotation is its remedy.
- **Unanchored roots (§2.5, the relays' L5 rule).** A client holding no version of an identity may accept any version that verifies on its own as an unanchored root. While the held history has no version 1 behind it, a later version from the same `ik` with a higher `ver` than everything held that doesn't chain replaces it outright. History anchored at version 1 is never replaced this way; gaps there are filled, or jumped over explicitly with a "history gap" warning.
- **Branches with a transfer win (§3.3).** A branch that leaves the client's chain where the chain is not yet final, and that contains a valid transfer anywhere along it, beats the chain's branch (which then contains none); otherwise the lower `jwsHash` where they part wins. Clients keep valid off-chain versions so a branch can be completed later. So bootstrap and incremental receipt reach the same chain from the same set of versions.
- **Out-of-order versions (§3.3).** A client holds a version whose parent it lacks only if its `ver` is at most the head's `ver` + 64 and it is signed by the head's owner or by an owner a held version hands over to; the oldest such version is dropped first.
- **Join confirmation (§3.3).** The "other" confirmer must be listed in the offered head's `members`, and is neither the owner, the inviter nor the viewer.
- **Accepts carry the invitee's `doc`** (optional), next to its friend `cap` (§5.3), so the inviter can reach it with no lookup.
- **`circle` envelopes** may also carry `ops: [<proposal jws>, …]` (§3.3 "Delivery"). The `~circle` sid is reserved like `~contact`; roster session ids never start with `~`.
- **Linking bytes (§2.4).** `s` enters `lid` and the compare code as its raw 16 bytes, after the UTF-8 prefix; HKDF salts are empty. The response frame is `{fkpk, n, epk, ct}`; its key also mixes in `HKDF(s, info "p2p/v3/link-key")`, and its AAD is `"p2p/v3/link|" + lid + "|" + did`, so a relay that doesn't know `s` can't substitute a response.
- **What counts as revocation (§2.5) [pre-release review S2].** A non-merge version revokes every `did` its parent listed and it doesn't. A merge revokes only a `did` listed by **both** parents and absent from the merge. A `did` linked on one branch only, and so dropped by the merge (which may never add a device), was not revoked: the owner's next version may list it again. Both the "a revoked `did` never returns" check and the jump denylist follow this. Demoting a key holder is not revocation, and no denylist applies to `keyholders` (they are the head's, within the allowlist) [S3].
- **Identity documents (§2.5).** `by` must be one of the version's `keyholders`. A merge's `keyholders` must also be a subset of both tips' `keyholders`. A version may not re-list a `did` that an ancestor listed and a later ancestor dropped (a revoked `did` never returns).
- **dns proofs (§2.6).** The canonical `loc` is the queried name, `_p2p.<claim>`; claims are lowercase.
- **Proposals (§3.3).** `promote` of a non-member is refused (rule 4); a `rename`'s "target" is the name. A proposal whose effect already holds is skipped, and its nonce is still recorded.
- **Restore (§2.7) and rule 6 (§5.2).** A restored device isn't listed in the document the relay holds, so rule 6 would refuse it, and it could never publish the version that lists it. Relays therefore answer such a device (valid under rules 1–5, unlisted) with `{"t":"ok","restricted":true}`: the connection has no mailbox, and every frame but `identity` gets `forbidden`. Publishing a version that lists the device makes it a full connection. Documents still have to verify under `ik`, and a restricted connection may only publish a version on top of the held history (extending every tip, or merging them), never a fork or a new root. Restricted connections have their own small per-userId cap, close after 60 s if not upgraded (and at certificate expiry), and are charged to their own identity rate limit only for a parsable document. A version whose parent the relay doesn't hold is answered `identity-gap`, so the restoring device back-fills the missing versions. Each of them extends the only tip.

  Relays judge a new version against the state they hold now:
  - chain and merge shape;
  - `by` is one of the version's key holders;
  - a merge's devices lie within both parents';
  - over a restricted connection, it sits on top of the tips.

  No-return (a revoked did is never re-listed, §2.5) is enforced by clients from their own chains (core `revokedAlong`), not by relays. Only identity-key holders publish versions, so a revoked ordinary device can't re-list itself. What a relay does remember is which dids a held version lists that the allowlist doesn't: those devices get no connection at all, not even a restricted one (a restore always brings a new did). When a relay discards history (a tombstone, a replaced root), it keeps those dids for 91 days, longer than any device certificate, and every connection closes when its certificate expires.

  Clients treat `restricted` as "this device isn't allowed" except while restoring. (`packages/relay`, `packages/p2p`.)
- **Rotation (§2.8).** How a rotation reaches each party. (`@peer2peer/core/v3`, `packages/p2p`.)
  - **The final version carries the statement.** An identity document MAY carry `"rotation":{"old":<half signed by the old ik>,"new":<half signed by the new ik>}`, and only on a version that lists no `devices` and no `keyholders` and isn't a merge. It is valid when both halves verify (`verifyRotation` without its clock), `from` is the document's `iss`, the old half's `ik` is the document's `ik`, and its `iat` is at most the document's `iat` plus the usual skew. Relays accept it through the core's document validation; with no certificates the document is far under the 16 KiB cap. We put it in the identity document rather than a separate relay endpoint because the document is already hash-chained, self-certifying and fetched from every listed relay every 10 minutes.
  - **The final version is terminal.** No version may name a rotation version as `prev` or `merge` (`identity-rotated`), and a client holding one never replaces its history, by a gap jump or as unanchored history. A sibling of the final version (a fork) leaves the intersection allowlist empty. Relays refuse a child through the same link check. They don't remember a rotation once they drop the history (a tombstone, after the head has been expired 90 days, or an unanchored root replaced by a newer version): a holder of the old `ik` could then start a new history at that relay. That matters only to such a holder, and buys nothing against clients, which judge from their own chains and keep the final version. `IdentityView.rotations` lists the statements the tips carry: two different ones are a conflict.
  - **Friends (the fast path).** A `contact` envelope MAY carry `{"rotation":{old,new},"invite":<invite JWS>}` instead of `text`. It is from the new identity (`rotation.to == from`); the invite is the new identity's, bound to the recipient (`aud` is its userId, never `*`), with the usual `ik`, `relays`, `doc` and contact `cap`. Receivers verify both, and hold it for their user as "<friend> moved to a new key" (§2.8: only after asking). Approving re-verifies the invite against the refreshed head (P3 above), refreshes the old identity (which may carry a competing rotation), refuses on any conflict, and refuses unless the old identity's own final version carries this same statement: a statement the old identity never published (say, signed with a stolen `ik` and sent around) can't split it from its friends. Then it runs the normal accept, and ends the old friendship locally (an unfriend kept on the user's own devices, and the old identity's caps revoked). From someone who was never a friend of the old identity, it is an ordinary held invite.
  - **Circles.** Where the old identity is the owner, the rotating device holds both keys: the old owner adds the new identity, the new identity joins, the old owner hands over with `transfer` carrying the new identity's consent over `{cid, ver, prev}`, the old identity leaves, and the new owner drops it. Where it is a member, a `circle` bundle MAY carry `rotation` next to the new identity's join and the old identity's leave, sent to the owner (with the owner's join cap). The owner's client applies it by itself, swapping old for new as a member in one version, only when the old identity's own final version carries the statement, the old identity is a current member it didn't remove before, the new one isn't blocked, no other rotation from the old id is known, and the owner doesn't hold changes for approval (§3.3, the hold policy). Admin rights are never carried by themselves: they wait for the owner. Anything else is held as a `rotation-join` (and re-checked when the final version shows up); the old identity's leave that came with it waits too. Approving needs the same final version. The old identity's leave also goes to every other member.
  - **The user's other devices.** The rotating device sends each of them a `sync` from the old identity: `{"rotation":{"statement":{old,new},"link":"p2p-link:…","keyholder":true?}}`, with a §2.4 link code minted by the new identity (its new device opens the link mailbox) for that device alone. A device takes only a sync from one of its identity's current key holders (only they hold `ik`) and only a statement from its own identity, and it never follows by itself: the rotation is held, showing the new fingerprint and the sending device, until its user follows it there. A key-holding device never follows: it alerts. Because the code travelled only inside an end-to-end encrypted `sync` to that one device, it stands in for the compare code: the rotating device certifies the one request whose MAC verifies, and several valid requests still abort. A device that doesn't answer before the final version is published re-links by hand later.
  - **The plan, and dropped devices.** The rotating client shows the new fingerprint and the devices that would follow before anything is published; devices the user drops are revoked on the old identity (the next version without them) before any link code goes out. The final version needs a backup of the new `ik` or a key-holding device that followed (§2.5 liveness).
  - **Approvals that turn out contested.** A client that already carried something over through a rotation (accepted the friendship, swapped the member into a circle it owns) and then learns of a second rotation from the same old id suspends every identity it carried over to at once: no delivery, no session access, no circle standing (a local block), and the caps issued to it revoked at its relays. It alerts its user, who checks out of band and keeps one identity or neither; the rejected ones' friendships end, they leave the circles this owner swapped them into, and they stay suspended. The approvals, the suspension and the settlement go to the user's other devices by `sync` (a settlement is taken from a key holder only, and only a key holder settles); the owner's key holder takes suspended identities out of the circles it owns when the dispute begins, and puts a kept one back. An identity the user kept is not suspended again by a later rotation from the same old id: that is a new dispute. A device never acts on another device's dispute report as claimed: the report carries the statements, and the receiving device suspends (and, on a key holder, removes from circles) only identities in a conflict it verified itself from statements and documents; an unverifiable report changes nothing.
  - **Known denial of service.** Anyone holding the old identity key can publish a competing rotation (even an invite-only one, with no final version) whenever they choose. Every client that already carried the honest rotation over then suspends the new identity and the owner's key holder takes it out of the circles it owns, until the user keeps it again after checking out of band. This is accepted by design: clients can't tell a timed conflict from a real compromise without the user.
  - **Which devices the plan lets follow.** By default only devices listed by versions this device published itself (its publish log) and seen in the last 30 days (an envelope from them, or a certificate issued); any other device, possibly one a thief's version added, is dropped unless the user keeps it explicitly, and a label from a version this device didn't publish is shown as untrusted. This holds for a contest too, whose plan lists from the version the other rotation replaced; a contest also drops, by default, the device that signed the other rotation's final version and every other key holder.
  - **Which friends get the new identity's invite.** Only friendships whose side of the rotating user was signed by the rotating device or a device the plan keeps (and, in a plain rotation, that verify now; a contest also takes stored ones the other rotation left unverifiable). Any other friendship, which a thief's device could have planted, is shown in the plan and invited only on the user's explicit opt-in; the plan's count is exactly who is invited. During a rotation window a device doesn't take, from another of its devices' sync, a friendship signed by a device it can't vouch for.
  - **Alerts and contest.** Every device alerts on a rotation of its own identity that it didn't publish (its publish log). A key holder may contest: it makes its own rotation and publishes its final version beside the other one (a sibling of it, on the version the other replaced), so the document carries two rotations and receivers apply neither. If relays already refuse its old device, the contest's invites alone make the conflict at each friend.

### P4. Short-code invites
A friend invite, and optionally circles to join, behind a short code that one command redeems. Nothing in §3.1 or §3.3 changes: the code carries an ordinary invite, and joining still follows §3.3.

**The code.**
- The secret `s` is 100 random bits, carried as 13 bytes, big-endian, whose top 4 bits are zero. 100 bits keeps even a malicious relay's offline search, which tries codes against the `lid`s it holds, out of reach across many codes.
- It is shown as 20 Crockford base32 characters in groups of four, after the relay part: `<relay part>/K7QM-3XPD-9TWA-HF2N-6RJC`.
  - The relay part is the canonical relay URL (§5.1) without `wss://`, and without the path when the path is exactly `/v3`.
  - Readers ignore case, hyphens and spaces, and read `O` as `0` and `I`/`L` as `1`.
  - A bare code (no relay part) is looked up on the redeemer's own relays.
- **The web link** `https://ix-infra.com/p2p/invite#<relay part>/<CODE>` carries the same code; the part after `#` (with the secret) is never sent to the web server. Readers are strict: `https` only, host exactly `ix-infra.com` (no port or user info), path exactly `/p2p/invite`, no query, and a fragment that is a relay part (`host[:port][/path]`, a DNS name or `[IPv6]` host) and the code. They check the text as typed, not a normalised URL: whitespace or control characters anywhere, dot segments (`/p2p/./invite`, `..`), percent-encoding in the path, or a `?` (even an empty query) are refused. Anything else that looks like a URL is refused too.
- **Private relays are opt-in.** Opening a code connects to its relay before anyone says yes, so a code (link or bare `relay/CODE`) whose relay host is loopback, link-local, private or otherwise not public unicast (`localhost`, `*.localhost`, `*.local`; 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16, 198.18/15, 224/4, 240/4 and 255.255.255.255; IPv4-compatible `::/96` including `::` and `::1`; fc00::/7, fe80::/10, fec0::/10, ff00::/8; Teredo `2001::/32` (whole); and IPv4-mapped `::ffff:0:0/96`, IPv4-translated `::ffff:0:0:0/96`, NAT64 `64:ff9b::/96` and 6to4 `2002::/16` addresses whose embedded IPv4 address is one of those, plus the local-use NAT64 `64:ff9b:1::/48`) is refused unless the user opts in (`p2p join --allow-private-relay`, or `P2P_ALLOW_PRIVATE_RELAY=1`), as for a team relay on their own network. A DNS name is checked where it resolves: the connection that opens the code resolves the code's relay host once, refuses it when any address it resolves to is in those ranges (`127.0.0.1.nip.io`, `localtest.me`, a rebinding name), and dials the address it checked, never resolving again. The HTTP fetches of the inviter's identity document from the code's relay go through the same check. A bare code with no relay part is looked up on the user's own relays. The relays the code's invite names (the inviter's) get the same check before anything is shown or accepted; refused, the code stays kept on the device, and the same command with the opt-in joins. Pasted long links get it too, with the same opt-in: `p2p accept <link>` on the relays the invite names (its `relays`, its bundled document's and its cap's), `p2p circle join <link>` on those of the link's owner hint (document and join cap): literal addresses at parse time, names resolved once up front for a clear error, and every connection to those relays (WebSocket and HTTP) through the same resolve-time check. The user's own relays (as they are when the command starts) are never refused or guarded, whatever their address: a team on its own Tailscale or LAN relay needs no opt-in between members. A relay guarded at the start of a command stays guarded for the rest of it, even when it becomes the user's own meanwhile (a code join whose new identity has only the code's relay). Invites that arrive otherwise (held for approval, a friend's rotation) are accepted as before, without this check: the person approves someone who already reached them.
- `lid = b32(SHA-256("p2p/v3/invite-id|" || s))[:26]`. The relay sees only `lid`.
- The bundle `{"v":1,"invite":<invite JWS>,"circle"?:{"head":<circle version>,"chain"?:[<versions from 1>]},"circles"?:[{"head":<circle version>},…]}` is sealed with ChaCha20-Poly1305 (RFC 8439). `circle` is the (first) circle the code joins; `circles` [protocol 3.1 addition] holds up to 4 more, heads only (the inviter sends each chain when it adds the redeemer), and appears only beside `circle`. A client from before `circles` ignores it and joins only `circle`, and the inviter's adds of the others reach it as ordinary circle invites for its user to approve: an accepted downgrade, so `circles` isn't critical. Clients advertise `invite.circles.v1` in their caps. Sealing:
  - key `HKDF-SHA256(ikm = s, salt = empty, info = "p2p/v3/invite-key", 32)`;
  - a random 12-byte nonce;
  - aad `"p2p/v3/invite|" || lid`;
  - `blob = b64u(nonce || ciphertext || tag)`.
- The invite JWS carries the inviter's `ik`, relays, identity document and a contact cap (§3.1, §5.3). Its `aud` is `*`, or one userId when the inviter bound the code to a recipient (`--to`). It expires with the code. When the first circle's chain doesn't fit the relay's blob cap, it is dropped (the inviter sends it on the accept); a circle is never dropped: when the heads don't fit, no code is made, and the inviter is told to name fewer circles. Every circle named must be one the inviter may add people to (its owner's key holder, or an admin) and not open; otherwise no code is made, and the error names the circle.

**The relay's invite mailbox.**
- `{"t":"invite-put","lid","blob","ttl"}`: authenticated (not over a restricted connection).
  - `ttl` is in seconds and is clamped to `inviteTtlMaxSec` (7 days). The reply is `{"t":"ok","exp":<seconds>}`.
  - A `lid` already held is never overwritten (`exists`), by anyone.
  - Limits:
    - `blob` ≤ `inviteBlobBytes` (32 KiB, `too-large`);
    - puts per userId and per source IP per hour (`rate-limited`);
    - open invites per userId (`full`);
    - open invite bytes per source network (`inviteBytesPerIp`, an IPv4 address or an IPv6 /48; `full`).
  - **Global budget.** The last tenth of the global byte budget is reserved: past 90%, a userId the relay first saw (its oldest held identity document) less than `inviteYoungIdentitySec` (a day) ago gets `full`. When the budget is exhausted, the relay doesn't refuse everyone: the userIds holding the most invite bytes (a per-userId counter) lose their newest invites until the put fits, each leaving an `evicted` tombstone. A flood costs the flooder first.
  - Persisted (a relay restart keeps open invites).
- `{"t":"invite-get","lid"}`: no auth needed. It returns `{"t":"invite","lid","blob"}` and deletes the invite (single use), or `not-found`.
  - Every get costs a per-IP token (`inviteGetsPerIpPerMinute`, default 10).
  - A miss costs one more from a much smaller hourly budget (`inviteMissesPerIpPerHour`, default 30), and once that is spent, every get from the IP bucket is refused until it refills.
  - At 30 misses an hour, a million IP buckets guessing for a week against a million open codes find one with probability below 10⁻¹⁴.
- `{"t":"invite-list"}` returns `{"t":"invites","lids":[…],"evicted":[…]}`: the putting user's live lids, and the lids the relay evicted to make room (kept as tombstones until they would have expired, so an inviter can tell an evicted code from a taken one). `{"t":"invite-del","lid"}` deletes one of them. Both are authenticated and act only on the caller's own invites.
- **No non-consuming read.** We considered an `invite-peek` and left it out:
  - Taking the blob is what lets an inviter notice an intercepted code. A peek would let someone who saw the code read the bundle (the inviter's identity, contact cap and circle) without leaving a trace.
  - The redeemer's look before consenting (`p2p join --preview`, or the question `p2p join` asks) happens after the take, from the copy kept locally: a redeemer who declines can still join later with the same code, and nobody else can use it.
  - What a redeemer fetched is kept locally, so a retry needs no second get.

**What the relay can and can't do.** The relay never receives `s`; it holds `lid` (a hash of `s`) and an opaque blob.
- It can't read the bundle.
- It can't substitute another, because a blob sealed under any other key, or altered, fails to open, and nothing is accepted.
- It can withhold the blob or burn the code, which is a denial of service only.

**Members-only relays (relay policy, not a protocol change).** A relay may admit only some userIds (docs/run-a-relay.md). It refuses anyone else at `auth` with `{"t":"error","code":"not-member"}` and closes with 4001; it closes live connections the same way when a userId stops being admitted. Three optional fields carry what a code needs there; open relays ignore them:
- `invite-put` may carry `"admit": b64u(SHA-256(k))`, where `k = HKDF-SHA256(ikm = s, salt = empty, info = "p2p/v3/relay-admit", 32)`. On a members-only relay a full member's put records a single-use grant that lives as long as the code (the reply adds `"admits":true`); a provisional member's put with `admit` gets `forbidden`.
- `auth` may carry `"admit": b64u(k)`. A userId that isn't admitted but presents the key of a live grant is admitted provisionally (the reply adds `"admitted":"invite"`), and the client forgets the key. The relay learns `k` only when it is used, and only someone holding `s` has it; `invite-del` voids the grant even after the take.
- A relay that follows a circle adds `"circle":{"cid","ver"}` (`ver` 0 before it holds one) to a full connection's auth reply. Members send `{"t":"circle-put","versions":[…]}` (at most 64 versions per frame) when they hold newer versions; the relay verifies them with the §3.3 chain rules and answers `{"t":"ok","ver","status"}`. Only an allowlisted userId may send the first (from version 1), and never for an open circle (anyone may join one); a head that turns open admits nobody through the circle until it is invite-only again. A client pushes a chain only to its own relays (listed in its identity document) and only for a circle it is a member of: a chain names every member.

**One yes, then the join.** `p2p join <code or link>`:
1. takes the blob, opens it, and verifies the invite as §3.1 does (including the inviter's head from its relays). A code bound to another `aud` is refused, and nothing is sent.
2. shows who it is from (address and fingerprint), whom the code is for when it names one (`aud`), and every circle it joins, and asks once. Nothing is accepted without that yes (`--yes` for scripts; the Claude mod's Join button after `--preview`). A code's circle versions are whatever its maker put there, so each is checked before it is shown: a version 1 as a genesis, a later one under its own `ik` (signed by the owner it names; a transfer version only with the first circle's chain). The preview shows each verified version's name, member count, policy and owner. A circle is joined on the yes only when its version verified, it is not open, and the inviter is its owner or an admin in it; any other one is shown as such ("unverified", "open", or "which they don't run") and is never joined from the code: if its invite arrives, it is a held circle invite to approve on its own. A code made for someone else is refused before any identity is created (a new identity can't be its `aud`); the code stays kept locally.
3. accepts: the friendship and the accept with the friend cap, as §3.1. Nothing is held for approval.
4. when the bundle names circles, waits briefly for the inviter's client to add the redeemer to each, then joins each under §3.3. The circle that arrives is checked against what the user said yes to before it is joined: its chain must verify from version 1, it must not be open, the inviter must be its owner or an admin, and its cid, name, policy and owner must match the preview (the redeemer keeps that snapshot with the pending code join). The same check runs again on the head the join actually commits to, since §3.3 joins the newest consistent chain the members answer with, which may be newer than the offered head (a circle that turned open since is refused there). If any differs, nothing is joined from the code and the circle invite stays held for the user's own approval. A code never makes an open circle the default. The confirmation rules are unchanged: an unconfirmed join needs the user's say, either `--yes` or a held item to approve. The code's first circle becomes the default circle only if the user has none; an existing default is never changed, and sessions already running don't move into a circle the join made the default (new ones start in it).

If the inviter's client isn't running, the join finishes after the next drain that brings the circle, which is the redeemer's next command.

A redeemer without an identity gets one first, on the default relays only (the inviter is reached through its own relays). With no default relays it gets the code's relay only. A relay chosen by whoever made the code sees when the newcomer is online and could drop their mail, so that is never silent: the client warns, `--json` carries `relayWarning: "<host>"`, and `p2p relays add` publishes the next document version with another relay.

**The inviter auto-completes.** Issuing the code was the inviter's consent. On the accept of a code's invite, the inviter's client:
- records the friendship, as for every accept;
- adds the redeemer to the circle. The owner, on a key-holding device, publishes the next version. An admin proposes the add to the owner and sends the circle as it stands.
- tells the user `"<name>@<fp> joined via your code K7QM… ("<label>")"`, with `p2p remove <userId>`, and logs a `p2p.joined` event.

The label is local only and never leaves the inviter's devices (they sync code records among themselves).

**Interception.** Whoever redeems the code first gets in. The mitigations:
- The inviter is told who redeemed it, and `p2p remove` unfriends them and takes them out of the circles the inviter's codes added them to.
- `p2p invites` shows a code as `taken` when the relay no longer holds it but nobody has joined.
- `p2p invites revoke` deletes the code at the relay, revokes its contact cap, and makes the inviter's client refuse that invite's accept even from someone who took the code before the revoke.
- `--to` binds the code to one recipient.
- Codes are single-use and live at most 7 days.

## Roadmap and open questions
- **Metadata privacy and optional Tor transport** ([RFC 0001](rfcs/0001-metadata-privacy-and-tor.md), accepted 2026-10-23; the privacy phase after the footprint work). It specifies:
  - sealed sender, with relay-side admission by recipient-issued sealed delivery tokens or `sub:"*"` caps, and PoW kept on first contact;
  - size padding to six buckets;
  - optional timing cover traffic;
  - optional two-hop relay-to-relay forwarding;
  - an opt-in `transport: tor` with `.onion` relay addresses;
  - bring-your-own egress for agents' web access, as configuration of the agent runtime only.

  Relays never act as exits to the open web. Each piece is cap-gated and rolled out like the status caps amendment. Until each phase's PR lands its own spec text here, nothing in §1–§8 changes, and §7's statement of what relays see stands.

## Review log (draft 3)
These were fixed in response to the pre-release review.
- **C1:** circles need member consent (join statements), and the viewer must have joined. Blocks are defined.
- **H1:** circle versions are hash-chained (`prev`) and contiguous, and each is signed by an admin of `ver-1`. A fork freezes the circle.
- **H2:** device linking uses a 128-bit secret shown on screen, with the new device's request MAC'ed. The 24-bit check code is gone.
- **H3:** identity documents are hash-chained and are the device allowlist. `ik` lives only on key-holding devices. Forks are treated as compromise.
- **H4:** `did = H(spk)`, mailboxes are keyed by `(iss, did)`, and `send` carries the recipient userId.
- **H5:** clients check `hello.relay` against the URL they dialled, and canonical relay URLs are defined.
- **M1:** identity documents expire after 30 days and are fetched from all listed relays; clients fail closed on expiry. Device certificates last 90 days.
- **M2:** displayed fingerprints are 80 bits, and petnames are supported.
- **M3:** proof verification steps are spelled out.
- **M4:** caps are bound to relays and kinds, `*` caps are limited, and only the issuer may revoke.
- **M5:** one sanitizer for all peer text, plus path rules.
- **M6:** pre-auth link mailboxes.
- **M7:** circle bundles can span envelopes, signer validity is judged at signing time, and heads are re-sent with gap requests.
- **M8:** caps for circle co-members.
- **M9:** the relay's view of the friend graph is stated honestly.
- **L1–L5:** a single `undeliverable` code; strangers' invites are held; replay retention and liveness by `ts`; the `did`/`kid` checks are restated; extensions need consent and badges carry a namespace.

### Second re-review (draft 3, revision 2)
- **N1:** expiry warns at first and fails closed only 60 days after `exp`. Own-device `sync` is exempt, relays and senders ignore expiry, and users are prompted at `init` for a backup or a second key holder.
- **N2:** honest identity forks are kept, not treated as compromise. The intersection of the device allowlists applies until a merge version. One device is the scheduled writer. Compromise is detected by the owner's devices seeing versions they didn't publish (`by`).
- **N3:** concurrent circle versions settle by lowest `jwsHash` among valid siblings. There is no freeze, and the user is alerted only for a disputed removal.
- **N4:** a new circle version (and a membership statement) needs a signer that is valid when received. Accepted history is kept, and admins re-sign the head when its signer is revoked.
- **M1:** friend caps flow in both directions (a `contact` grant from a stored friend).
- **M2:** circle invites can go by `contact` to non-friends.
- **M3:** a circle-scoped cap in each join statement.
- **M4:** the link secret names its relay; the new device shows a compare code; the MAC uses length-prefixed fields; slots are tagged `req`/`resp`; more than one request aborts the link.
- **M5:** rotation re-keys devices.
- **M6:** gaps that can't be filled can jump to a head under the same `ik`; publishers back-fill.
- **M7:** leave statements go to every member, ordered by `n`.
- **L1:** a cap-less contact to an unknown mailbox answers `sent`; the `link` cap kind is removed.

### Third re-review (draft 3, revision 3)
- **R1:** circle versions become final once a child is accepted. A sibling replaces the head only when its signer is an admin of both the parent and the head, so removed admins can't rewrite history.
- **R2:** bootstrap needs the full chain from version 1. Only the new head's signer must be valid now; history is vouched for by `prev`, with signatures checked against any listed certificate of the signer. Invites show the founder's and the inviter's addresses. A conflicting chain after joining raises an alert.
- **M1:** merges come from the single writer, may only shrink the device list, and are the one `ver` exception. A `tips` and `chain` fetch API is added.
- **M2:** join caps name no circle, and are renewed before expiry.
- **M3:** members re-sign membership statements after device revocation or near expiry.
- **L1:** `n` is kept in step across a user's devices by `sync`.

### Fourth review (draft 3, revision 4)
- **H-A, H-B, and the remainder of R1/R2:** circles now have a **single owner** whose `ik` signs every version. Admins sign proposals, which the owner's client applies. Ownership moves only by a `transfer` the new owner counter-signs.
  - Siblings can only come from the owner's own devices and settle deterministically (lowest `jwsHash`), with no arrival-order finality.
  - A removed admin never had signing authority, so it can't fork the circle or capture members.
  - History is self-certifying (`ik` = owner fingerprint), and checkpoints keep bootstrap bounded.
- **Mediums:** a `keyholders` list in the identity document for the single-writer rule; the chain walk follows `merge`; history needs no certificate lookups.
- **Low:** `leave` wins a tie on `n`.

### Fifth review (draft 3, revision 5)
- **High 1:** only the owner of the client's current head can sign a replacement version, so everything at or before the latest transfer is final. A former owner can't rewrite history.
- **High 2:** checkpoints are removed; bootstrap always takes the full chain. Invites show the founder, the owner and the inviter, and flag a change of owner.
- **Mediums:**
  - proposals are de-duplicated by `nonce`, dropped as stale using `base`, and re-sent only while unapplied;
  - owner devices alert on circle versions they didn't publish, and a compromised owner means re-creating the circle;
  - joins may name any ancestor, and the owner prompts re-signing after a discarded branch;
  - rule 2's "expired" means the fail-closed state;
  - owner loss is documented.
- **Lows:** transfer consent covers `prev`; admin powers are documented; `keyholders` are intersected during a fork.

### Sixth review (draft 3, revision 6)
- **High (remainder of high 1):**
  - a transfer is canonical against a non-transfer sibling, so a former owner can't race its own handover;
  - two different transfers freeze the circle and alert;
  - before joining, a client confirms the head with the owner and one other member, and refuses on any conflict.
- **Mediums:** proposals and applied nonces are bounded to 30 days, and a stale proposal is reported back to its admin.
- **Lows:** a frozen circle shows a notice to members, and the owner's own devices receive every circle version.

### Seventh review (draft 3, revision 7)
- **High:** a transfer-equivocation freeze applies only at the transfers' parent or during bootstrap. Clients already past a transfer ignore siblings from non-current owners, so a former owner can't freeze the circle.
- **Medium:** join-confirmation members are chosen from people the user already knows, or at random.

### Status forward compatibility (draft 3 amendment)
- Approved by the CEO as an amendment of draft 3, with no `v` bump, because nothing is public yet. It is phase P0 of the subagent-status and Ix-footprint design, and must be the floor before any later status field (`agents`) or extension state kind is sent.
- §4.3: receivers MUST ignore unknown top-level `status` fields and drop them before storing, showing or delivering anything. Known fields stay strictly validated. Everything else that security depends on stays strict: signatures, ids, kinds, sizes, the outer plaintext and every other kind's plaintext.
- §4.3: the new `caps` field, bounded to 16 distinct entries of at most 40 characters in a strict charset, with `status.tolerant.v1` advertising the rules above. Peers use it to decide what newer fields or kinds a session can take.
- Two-step rollout, so peers that haven't upgraded don't lose sight of upgraded ones: this release doesn't send `caps` unless the user opts in (`P2P_STATUS_CAPS=1` or `statusCaps` in config.json; an explicit `--cap` without it is a usage error). A later release (P1) turns emission on by default.

### Status agents (draft 3 amendment, footprint P1)
- Approved by the CEO (2026-10-22) with the subagent-status design: subagents share exactly the session's audience under the same switch, agents spawned by plugins or tools are not hidden, the task line is the spawn's description (no model call), and prompts, transcripts and final answers are never sent.
- §4.3: the new `agents` field and cap `agents.v1`, strictly validated (at most 8 entries of fixed fields; session-local ordinal ids; depth-2 nesting with no cycles; an 80-character sanitized task; at most 10 repo-relative files each), re-validated before display. Old clients get `(+N agents)` in `summary`.
- Per-recipient: status is one plaintext per user, so `agents` goes to a user only when all their known live sessions advertise `agents.v1`; a user with a mixed or unknown set of devices gets the summary fallback.
- Rollout step 2: statuses carry `caps` by default; `P2P_STATUS_CAPS=0` or `"statusCaps": false` opts out.
- Review lows of the amendment's first release: a caller's `--cap` never fails a status post (L3: off, invalid or surplus caps are left out with a warning); the Codex bridge never passes `P2P_STATUS_CAPS` from its env to `p2p` (L2); `statusHasCap` tests a real array only (L1).

### Default rosters follow the default circle (live bug, footprint P1 PR)
- Found live: a session started before its user's circle join completed (or before the default circle was set, or set on another device) kept the private roster it was first signed with, so its statuses reached only its owner, while friendship, caps and relays all checked out. The client now re-signs a roster nobody set explicitly to match the current default (both ways), and reads it after draining what is queued, so a join approved in that drain counts for the same status.

### Footprint P1 review (pre-release follow-up)
- **M1:** a default roster's follow is decided and written under the state lock against the stored doc; versions only go up, and a stale or conflicting version in the trust store stops the write. A status post can no longer undo a concurrent `session roster --private`.
- **M2:** wording says running sessions nobody shared by hand follow the default too; a running session never auto-follows into an open circle (kept private, with a note).
- **M3:** a subagent's task line loses absolute and home paths and common secret shapes (provider tokens, PEM, JWT, long hex/base64 runs) on both the mod and the CLI side.
- **M4:** the mod's no-git repo probe reads only regular files (lstat, non-blocking, 4 KiB), requires the current user's ownership on POSIX, stops at home and never takes home's ancestors or the filesystem root, rejects `..` in a branch, and trusts a `gitdir:` only as `<repo>/.git/worktrees/<name>` linking back.
- **Lows:** `summaryAt` ignores the `(+N agents)` suffix; an agent entry's files share one root, so `wt` is never claimed for a main-checkout edit; ListAgents quotes agent types and frames agents as peer data.

### Footprint P1 second review (pre-release follow-up)
- **M-new:** a roster write numbers past the higher of state's and the trust store's versions, adopts a store version that is ahead (repairing state; it counts as set explicitly), and takes `same` as success. A store ahead of state no longer locks a session's roster for good.
- **Redaction:** one implementation (core `redact.ts`; the mod ships a verified byte-for-byte copy). Paths are stripped after `[ { ( < : , " '` too, plus `~user/` and `file:///`; slash commands like `/peers` stay. URL userinfo, `glpat-`, Stripe `rk_/pk_/sk_ live|test`, `xapp-` and `xoxe-` are redacted; a long run with `/` is a path only without `+`/`=`, with segments of at most 24 characters and a word or dotted segment, so an AWS-secret shape is redacted; git SHAs (40/64 hex) and UUIDs stay. The CLI sanitizes before stripping.
- **Probe:** a symlinked `.git` ends the walk with no root; on Windows an ancestor root counts only inside home.
- **Open circles:** a session shared with a circle whose policy is (or became) open is warned about once on its next status (result warning, mod toast).

### Extension state kinds (draft 3 amendment, footprint P2)
- Approved by the CEO (2026-10-22, decision 2) so the Ix footprint can travel as a session's latest value rather than an event that toasts every peer and reaches their model on each change.
- §4.3: the optional `state: {ttl}` marker on an extension kind's plaintext (strict; 10-3600 s), the cap `xstate.v1`, and each declared kind's cap `<kind>.v1`. Sent to the session's status audience only, and per recipient only to users whose live sessions all advertise `xstate.v1`, and only to those sessions' devices. Received only from the session's owner, latest wins per (sender, session, kind), never logged, toasted or shown to a model, dropped when the session goes un-live or the ttl lapses.
- Limits: 16 KiB per value; the sender's 5 s per kind and session; the receiver's spacing check, 120 values a minute per sender, 8 kinds per session, 64 KiB per sender and 512 values in all. `p2p ls --json` gets a bounded summary (no bodies); the Claude mod drops even that, so ListAgents, `/peers` and `<peer-activity>` never carry state (a `/peers` result is read by the model too).
- Folded-in lows of the pre-release review: a roster in the trust store that is ahead of state is adopted only when this device signed it (anything else fails closed with an error naming the other device), and keeps following the default circle when it is exactly the default roster this device would sign. Redaction: `; | * @ ! -` and smart quotes may come right before a path; a long run counts as a path only with a dotted extension or a lowercase segment of at least 3 letters; `password`/`passwd`/`secret`/`token`/`api_key` values and `Bearer` tokens are redacted.

### Extension state kinds review (pre-release follow-up)
- **M1:** one sender can no longer evict everyone else's state. At most 64 values per sender; every value is charged at least 1 KiB plus its fallback, kind, sid and overhead against the 64 KiB per sender; over the 512-value global cap, the sender holding the most loses their oldest value first (never another sender's by age). Each sender's values are stored in a document of their own, so an accept rewrites only that sender's document (and a small index when their totals change).
- **M2 (pre-existing):** a participant's `status` sent into the owner's session overwrote the owner's status record, because nothing required `from == own` for it. Core now rejects `status`, `idle` and `roster` from anyone but the session's owner (`not-session-owner`); `idle` would otherwise fire notify-when-idle subscriptions on a participant's word.
- **Lows:** a state value for a kind the loaded extension doesn't declare as state keeps only the fallback (L1); the fallback summary is documented as visible to anything that runs `p2p ls`, a model's shell included (L2); the receiver's rate window is per (sender, session) (L3); `Bearer` is matched in any case, and JSON- or quote-wrapped keyword secrets (`"password": "x"`) are redacted whole (L4).
- **Re-review (N1-N3):** the per-(sender, session) window alone left a sender's total unbounded (session ids are free), and each accept rewrote a rate map that only grew: there is now a per-sender ceiling of 240 a minute, the map keeps at most 128 open windows (stale ones pruned on every write). A sender's document is deleted once it holds no values and no open rate window, and on first use in a process the index is recomputed from the sender documents (a new sender is indexed before their document is written).

### Launch must-fixes (draft 3 amendment)
- **Same-second re-friend (§3.1):** unfriending and re-inviting within one second, or with the unfriender's clock ahead, had the new friendship refused as `unfriended` after the link or code was spent. The rule (H1) is kept; clients now date invites after every unfriend they hold (`inviteIatAfterUnfriends`), fetch what is queued first, and an invitee holding a newer unfriend refuses the invite before accepting anything (`unfriendEndingInvite`, error `invite_predates_unfriend`).
- **A stranger couldn't join a long-history open circle (§3.3, §4.3, §5.3):** a `want` from someone the member held no cap for was answered with one `contact` envelope carrying the whole chain; past about 35 KiB (about 6 versions of a 100-member circle) it exceeded the 64 KiB envelope cap, and the join never completed. A `want` now MAY carry an answer cap (`sub` = the member asked, `kinds: ["*"]`, at most 24 h), and the answer goes as ordinary chunked `circle` bundles under it; the joiner waits until every version from 1 has arrived. A member answers a non-member at most 3 times an hour per asker and at most 8 MiB an hour to all non-members; without a cap it answers only what fits one first-contact envelope. A shorter proof (the head plus the owner's transfer chain) was considered and rejected: standing needs every member's `at` on the held chain, fork and transfer rules are judged over it, and skipping versions would be the checkpoint review 5 (high 2) ruled out. Old members reject a `want` with `cap` as malformed (strict plaintexts), so this needs members on the amended client; v3 isn't public yet.

### Launch must-fixes review (pre-release follow-up)
- **H1:** a multi-part answer counted as complete after its first part (versions go out in order, so part 1 is a gap-free prefix); bootstrapping then failed with `circle-gap`, the join reported a conflict and dropped the pending join. Answers now carry `part: {id, i, n}`; an answer counts only once it reaches the offered head with every part of it, for the second confirmer too; `circle-gap` means waiting; a later try asks from the first missing version. Statements-only parts are recorded for a re-join of a circle still held (L5).
- **M4:** what a joiner keeps of an answer is bounded and filtered as it arrives: only the joined circle's versions, at most 256 above the offered head (a link may be older than the head the join confirms, review M3), at most two per `ver`, each at most 16 KiB; statements at most four per member; parts of at most 8 answers; a byte ceiling per confirmer. Each confirmer's answer is a document of its own, so a part never rewrites the joins index.
- **M1 (and L4):** a throwaway identity that auto-joined an open circle could then ask for the whole chain without limit, since members weren't limited. Every asker now has the count and a byte budget per hour, versions already sent within the hour go again only once, and the checks run before anything is built or fetched.
- **M2 (and L2):** many throwaway identities could drain the non-member budget, multiplied by counting every answer once per recipient device. An answer now goes to the asking device only and is counted once, at its sealed size times the relays used; askers who name a version they were offered (`want.link`) have a reserve the others can't spend; and an answer larger than what is left is cut and resumed from `fromVer` in later hours, so no chain is unjoinable for being bigger than one hour's budget.
- **M3:** every device of a member answered the same `want`. Now only the lowest key holder (else the lowest device) on the member's own document answers.
- **Lows:** answer caps are synced to the joiner's other devices and revoked when the join completes or is refused (L1); answers are charged at sealed size times relays (L2, with M2); the second confirmer's answer must be whole too (L3, with H1); the limits are checked before an answer is built or an identity document fetched (L4, with M1); statements-only parts count for a re-join of a circle still held (L5, with H1). `p2p doctor`'s clock warning notes that a peer skewed the other way reaches the limit sooner.

### Launch must-fixes re-review (pre-release follow-up)
- **N2:** members had only per-asker limits, and an open circle admits up to 20 a rolling hour. A circle's members now also share one pool per hour.
- **N3:** the reserve for non-members was keyed to `want.link`, any hash on the chain, and those are public (`prev`, the `at` of join statements, and every answer hands them out). It is now keyed to proof of work on the want, bound to the asker, the circle, `fromVer` and the asker's time, each proof accepted once. A per-joiner token signed by the owner or inviter was considered: an open circle's link is meant to be shared, so a token in it is no more per-joiner than the link, and minting one per joiner needs the owner online for every join, which a link can't wait for. Work costs every asker the same and needs nothing from the owner.
- **N6:** the answering election could stall for good (the chosen key holder lost, rarely online, or without the circle). The other devices now answer in turn after a delay unless an answer by one of them has arrived in `sync`; a device without the circle simply can't answer, and the next in line does.
- **N4:** an offered head that is a fork (a sibling not on the canonical chain) made the join wait forever. With every version up to its `ver` present, it is now a `join_conflict`.
- **N5:** a part that adds nothing to what a joiner holds (a duplicate, or everything over a bound) no longer rewrites the confirmer's document.
- **N7:** an answer cut by the budget could carry every version up to the head but not the statements, and still count as whole. A cut answer now stops short of the head; the head goes in the later answer that carries the statements.

### Pre-release review
- **F1:** a proof of work is bound to the member asked (`to`, the hash of its `ik`), so one proof can't be spent at several members. The work doesn't scale with the bytes granted; instead §3.3 now says plainly that a determined attacker can throttle open-circle joins and that the reserve only raises the cost.
- **F5 (release gate):** the `want` fields `cap`, `link` and `pow` and the bundle field `part` are rejected as malformed by clients from before them (plaintexts are strict). Before a public release, this needs a version gate: a client must know a member understands these fields (a capability it advertises, or a protocol version) before sending them, and fall back otherwise.
- **F2, F3:** the device fallback multiplied the shared pools by the number of devices (only answers were synced, and only into `last` and the per-asker counts). Now the reserve and open pools, the members' pool, spent proofs and refusals are synced too; deferred wants are dated by their envelope, expire after 30 minutes and are re-checked when answered; an answer that reached no relay isn't reported; cheap checks run before a want is held back, at most 4 per asker.
- **F4:** a joiner takes at most 4 new answers (part ids) from one confirmer per rolling hour (parts of answers it already tracks always count), and parses statements before storing them: only join statements for the circle being joined.
- **Soak regression (seed 7: "u1 couldn't re-join the circle"):** a joiner listed a member as asked only after every want had gone out, and since this PR solves a proof of work per want, that took long enough for a fast member's answer to arrive first and be taken by another process of the joiner's (its `watch`); an answer from someone not yet listed is dropped (review L1), and the member's per-asker limits then refused the re-asks. A join now lists the member as asked before its want goes out (and as due to be asked again when the want reached no relay).
- **Undelivered answers:** a member charged an answer, and marked it sent (and a resend as used), before delivering it. An answer that then didn't go out (its process closing, a relay down) left the asker's next wants refused for an hour. An answer that didn't fully go out is now refunded (bytes, pool shares, proof of work, and what was marked sent); it still counts against the asker's answers that hour, which bounds what failed deliveries can cost.
- **Answers per asker:** 3 answers an hour per asker refused a member who left and joined again a few times in an hour (each join needs an answer): it could not join until the hour passed (soak, seed 21). The count is now 10; the byte budgets (per asker, per circle, the non-member pools) still bound the cost.

### Delivery receipts (draft 3 amendment)
A live report: a sender's sessions said "Delivered" while the recipient never saw the messages (held for approval in an auto mode, or in a session nobody was watching). §4.3 "Delivery receipts" adds `msg.rcpt` and the `receipt` kind (sid `~receipt`) behind cap `receipts.v1`, so no client from before it ever receives either. It reuses nothing from the earlier text "delivery notice" (a `msg` a client sent its sender on a decline or an expiry), which stays for senders that didn't ask: a receipt carries no text and is never shown as a message.

### Forward compatibility (protocol 3.1)
A CEO request before launch: peers on different versions must interoperate on every feature they share. Core used to refuse any unknown field or kind, so a peer one release ahead could make every message fail. Amended: must-ignore for plaintexts and the outer envelope, the `crit` rule for signed objects, unknown kinds verified and surfaced once, device capabilities in the identity document (`dinfo`, two-step rollout) and in status caps, and relay features in `/.well-known/p2p-relay.json`. Policy, the list of every check that became lenient and why, the analysis of inherently critical fields, and the cross-version matrix: docs/compatibility.md.

### Pre-release follow-ups
- **N-A:** an answer that didn't fully go out was refunded entirely, so an asker steering the answer to a relay that drops one part got the rest for free, and the budgets never ran down. The member now charges what went out (each delivered part's sealed size times the relays it reached, at least 4 KiB an attempt) and refunds only the remainder.
- **N-D:** the joiner took 4 new answers from a confirmer an hour while a member may send 10; both are now 10, one constant.
- **N-B:** a member's answer records are bounded whatever the number of askers: the per-asker and per-circle maps keep their 2048 (circles: 512) most recent keys, and the pool lists fold their oldest entries into one, so evicting never frees budget already spent. A refusal repeated within 10 minutes no longer rewrites the record.
- **P1 (pre-release review):** a relay the asker controls could store every part and reply with an error, so nothing was charged and the proof of work came back. A member now charges each part for what it wrote to the wire (sealed size times the relays it was written to, whatever they replied); only parts that never left the client (no connection, no capability) are refunded, and the proof of work stays spent once anything was written.
- **P3 (pre-release review):** bounding the spent proofs of work could forget one still inside the window a proof is accepted in, which could then be replayed. Every proof spent in the last 20 minutes is now kept; only older ones are dropped beyond the cap.

### Web link domain
- **W1:** the web forms of invite and circle links move to `https://ix-infra.com/p2p/i#…` and `https://ix-infra.com/p2p/c#…`. A web link's fragment is readable by the page's script, so the host must be one the project controls; `peer2peer.dev` wasn't. Under the compatibility rules ([GOVERNANCE.md](../GOVERNANCE.md#compatibility-rules)), clients keep parsing the deprecated `https://peer2peer.dev/i#…` and `/c#…` forms (parsing is local, and earlier clients printed them) and never generate them. The `p2p://` forms are unchanged.
