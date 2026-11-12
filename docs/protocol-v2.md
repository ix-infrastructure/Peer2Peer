# Peer2Peer v2 protocol (draft 2)

> **Historical, never enabled.** v2 was a draft built around a hosted attestation authority and relay; it never shipped. It is kept only because [protocol.md](protocol.md) (v3) inherits its cryptography, envelope, replay window, friendship rules and rosters, and cites its sections (for example C4, C7, C13, C14, D6, D7, H1). Where this text names a hosted authority, relay or host keychain, v3 replaces it (see the table at the top of protocol.md).

> **Draft 2** changes draft 1 in nine places, each marked **[draft 2]** below:
> - the envelope carries the sender's certificate as `fcert` (D1) and the session owner as `own` (D2), and `own` is part of the AAD;
> - authorisation is two-sided (D3);
> - rules are given for the non-`msg` kinds (D4);
> - the AAD is fixed to a single form (D5);
> - the replay window accepts late delivery from the relay's 24h store (D6);
> - seq replay protection is a sliding window that tolerates reordering (D7);
> - a `contact` kind delivers invites, accepts and unfriends between users who share no session (D8);
> - a roster's `org` confers workspace standing only if the roster owner is attested in it (D9).
>
> They are summarised under "Draft 2 changes" at the end.

Binding spec shared by the hosted attestation authority ("the authority" below), the client core (`packages/core`), and a hosted v2 relay.

## Relationship to the authority
Peer2Peer is a distributed network of its own. Trust decisions happen on the devices, and the relay is dumb. The authority is its identity root:
- **Eligibility:** any authenticated account at the authority (an SSO sign-in with an active membership in at least one workspace) may register devices. There is no subscription or billing gate.
- **What the authority signs:** device certificates (key ↔ account), workspace attestations (account ↔ orgs) and the revocation list. It never holds private keys, and it never sees friendships, rosters or message content.
- **If the authority is down:** existing certificates and attestations keep working offline until they expire (30 days and 24 hours respectively). Only new devices and renewals need the authority.

## Primitives
- **Signatures:** Ed25519 (RFC 8032).
- **Key agreement:** X25519. **AEAD:** XChaCha20-Poly1305 (24-byte nonce). **KDF:** HKDF-SHA256. **Hash:** SHA-256.
- **Encoding:** base64url without padding, written `b64u` below.
- **Every signed object is a JWS in compact serialization:** `b64u(header).b64u(payload).b64u(sig)`, with `alg: "EdDSA"` (RFC 8037) and a mandatory `typ`.
  - The signature covers the exact bytes `b64u(header) + "." + b64u(payload)`. Verifiers never re-serialize JSON, so no canonicalization is needed.
  - A verifier MUST check `alg == "EdDSA"`, the expected `typ`, and the `kid` before trusting any field.

## Identities
- **userId:** the edge-verified, normalised email (lowercased, trimmed). It is the only person key.
- **deviceId:** `d_` + b64u of 16 random bytes, generated on the device.
- **Per-device keys:** an Ed25519 signing key (`spk`) and an X25519 agreement key (`kpk`).
  - The private halves never leave the device; they are stored in the OS keychain.
  - A host application may reach the keychain through a host capability, with service `ix-p2p` and account `<userId>/<deviceId>`.

## Objects signed by the authority (header `kid` = the authority's key id; key from JWKS)
- **The authority's JWKS:** `GET /.well-known/p2p-jwks.json` returns `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"<id>","x":"<b64u pub>","use":"sig"}]}`.
  - It may list more than one key, for rotation.
  - `<issuer>` below is the authority's fixed issuer string. The dormant reference v2 code in `packages/core` uses the issuer `kartr` and the error codes `unknown-kartr-key` and `kartr-signature-invalid`; v3 doesn't use them.
  - Clients cache it for 1h and refetch on an unknown `kid`.
- **Device certificate**, `typ: "p2p-device+jws"`:
  - Payload: `{ "iss":"<issuer>", "sub":"<userId>", "did":"<deviceId>", "spk":"<b64u ed25519 pub>", "kpk":"<b64u x25519 pub>", "iat":<s>, "exp":<s, iat+30d> }`.
- **Workspace attestation**, `typ: "p2p-workspace+jws"`:
  - Payload: `{ "iss":"<issuer>", "sub":"<userId>", "orgs":["<orgId>",...], "iat":<s>, "exp":<s, iat+24h> }`.
- **Revocation list**, `typ: "p2p-revocations+jws"`:
  - Payload: `{ "iss":"<issuer>", "dids":["<deviceId>",...], "iat":<s> }`.
  - Clients poll it every 10 min and reject anything signed by a listed device.

## Objects signed by a device (header `kid` = deviceId)
Every device-signed object travels with the signer's device certificate. A verifier checks the certificate first (the authority's signature, expiry, not revoked, `did == kid`), then verifies the object with the certificate's `spk`.

- **Friend invite**, `typ: "p2p-invite+jws"`, signed by the inviter:
  - Payload: `{ "iss":"<inviterUserId>", "did":"<deviceId>", "aud":"<inviteeUserId>" | "*", "nonce":"<b64u 16B>", "iat":<s>, "exp":<s, ≤ iat+14d> }`.
  - `aud:"*"` makes a shareable code: the first accepter binds it.
- **Friend accept**, `typ: "p2p-accept+jws"`, signed by the invitee:
  - Payload: `{ "iss":"<inviteeUserId>", "did":"<deviceId>", "inv":"<b64u sha256(invite compact)>", "iat":<s> }`.
  - Valid only if `inv` matches an unexpired invite whose `aud` is the accepter or `*`.
- **A friendship certificate** is the pair `{invite, accept}`.
  - It is valid while neither side has an unfriend for it. **[draft 2, review fixes H1 + re-review]** An unfriend from X about Y kills every friendship of that pair (whoever issued the invite) that meets either condition:
    - its invite is the one the unfriend names (`inv`), whatever the accept's `iat`;
    - its invite was issued at or before the unfriend (`invite.iat <= unfriend.iat`). This covers other invites still open at unfriend time, such as a shared `aud:"*"` code or a second invite.

    Only an invite issued after the unfriend can re-friend.
  - Friendship is between users, not devices. A user's other devices learn of it through a sync message to self.
- **Unfriend**, `typ: "p2p-unfriend+jws"`:
  - Payload: `{ "iss":"<userId>", "did", "peer":"<otherUserId>", "inv":"<hash of the friendship's invite>", "iat" }`.
- **Session roster**, `typ: "p2p-roster+jws"`, signed by a device of the session owner:
  - Payload: `{ "iss":"<ownerUserId>", "did", "sid":"<sessionId>", "ver":<int, strictly increasing>, "vis":"workspace"|"private", "org":"<orgId the session runs in>", "parts":["<userId>",...], "iat" }`.
  - Receivers keep the highest `ver` they have seen per `(iss, sid)`.

## Authorisation (evaluated on the receiving device, pure function)
`mayExchange(viewer, sender, roster, facts) -> bool`. A message is accepted when **all** of these hold:
1. The sender's device-certificate chain is valid (signature, expiry, not revoked) **and** the envelope signature is valid.
2. The **sender** satisfies one of (a), (b), (c) below.
3. **[draft 2]** The **viewer** (the receiving user) independently satisfies one of (a), (b), (c), using the viewer's own friendships and workspace attestation. **[review fix H1]** The viewer's side uses **only** friendships and unfriends from the viewer's own store, never a proof the sender presents. A sender-presented friendship can satisfy only the sender's side, and it still dies on the viewer's stored unfriends.

A user satisfies the rules when:
- (a) `user == roster.iss` (the owner, from any of their devices);
- (b) `roster.vis == "workspace"` and the user's valid workspace attestation includes `roster.org`;
- (c) the user is in `roster.parts` **and** (there is a valid friendship between the user and `roster.iss` **or** the user's workspace attestation includes `roster.org`).

**[draft 2, D9]** `roster.org` is chosen freely by the roster's owner, so on its own it proves nothing. Rules (b) and the org half of (c) apply, on the sender side and on the viewer side alike, only when the **owner** is attested in `roster.org`. That means a workspace attestation from the authority that verifies (the authority's signature, unexpired), has `sub == roster.iss`, and includes `roster.org`. The receiver gets it from `plaintext.ownerWorkspace`, or, when the sender is the owner, from `plaintext.sender.workspace`.
- An owner attestation that is present but invalid rejects the envelope (an invalid authority signature, an unknown authority key, `expired` or `owner-workspace-mismatch`).
- Without a valid one, `vis:"workspace"` grants nobody, and only rule (a) (owner) and rule (c) through friendship remain. A party who would have qualified only through the org is rejected with `owner-not-in-org`, on either side.
- Where the receiver finds the owner attestation, in order:
  1. carried in the envelope: `plaintext.ownerWorkspace`, or `sender.workspace` when the sender is the owner;
  2. when the receiving user **is** the owner, its own verified attestation, so teammates needn't relay it to the owner;
  3. a local cache: the newest verified owner attestation per owner, kept in the TrustStore with the latest `exp`. It is filled from carried attestations of accepted envelopes and re-verified on every use.
- The cache is still bounded by the attestation's own 24h lifetime. If an owner stays offline (and so stops refreshing its attestation) for longer than that, members lose org standing in its sessions until it reconnects, or until someone relays a fresh one. Friendship-based standing is unaffected.

So once B unfriends A, B rejects A's messages, even into A's own session, unless B still stands in the session through the workspace.

Non-owners can't re-share; only an owner signs a roster.

## Message envelope
`typ: "p2p-msg+jws"`, signed by the sender device (header `kid` = `fdid`). Payload **[draft 2]**:
```
{ "v":1, "from":"<userId>", "fdid":"<deviceId>", "fcert":"<sender device cert jws>",
  "to":"<userId>", "tdid":"<deviceId>", "own":"<session owner userId>",
  "sid":"<sessionId>", "seq":<int per (fdid,tdid,own,sid)>, "ts":<ms>, "n":"<b64u 24B nonce>",
  "epk":"<b64u ephemeral x25519 pub>", "ct":"<b64u ciphertext>" , "kind":"msg"|"roster"|"idle"|"sync"|"unfriend"|"contact" }
```
- **[draft 2] `fcert`** is the sender device's certificate. The receiver verifies it **before** opening the envelope: the authority's signature, expiry, not revoked, `did == fdid == kid`, `sub == from`. It then verifies the envelope signature with the certificate's `spk` and opens with its `kpk`. The relay already sees `from` and `fdid`, so `fcert` reveals nothing new. `GET /v1/p2p/devices` remains only for the **sender** to find a recipient's `kpk`; on first contact the sender presents its invite as `X-P2P-Proof`.
- **[draft 2] `own`** is the session owner. A session is identified by `(own, sid)`. Receivers look rosters up by `(own, sid)` and reject a roster whose `iss != own`. Replay `seq` floors are kept per `(fdid, own, sid)`.
- **Sealing**, per recipient device:
  - `ikm = X25519(eph, tdid.kpk) || X25519(sender.kpk_priv, tdid.kpk)`.
  - `key = HKDF-SHA256(ikm, salt=n, info="p2p/v1/msg|"+fdid+"|"+tdid)`.
  - `ct = XChaCha20-Poly1305(key, n, plaintext, aad)`.
  - **[draft 2]** `aad` is the UTF-8 of the fixed string `"p2p/v1|"+from+"|"+fdid+"|"+to+"|"+tdid+"|"+own+"|"+sid+"|"+seq+"|"+ts+"|"+kind`, with `seq` and `ts` written as decimal integers. `from`, `to`, `own` and `sid` must not contain `|`. (Draft 1's alternative AAD, `b64u(header)+"."+<payload JSON without ct>`, is dropped.)
- **Plaintext** is UTF-8 JSON: `{"text": "...", "roster": "<roster jws>"?, "ownerWorkspace": "<owner's attestation>"?, "sender": {"workspace": "<attestation>"?, "friendship": {invite, accept}?}}`. **[draft 2, D9]** `ownerWorkspace` is the session owner's workspace attestation. The owner's own messages carry it automatically, because `sealEnvelope` copies `sender.workspace` when `from == own`. Non-owner senders must relay the owner's attestation, for example when forwarding the owner's roster, or the org confers nothing on that message. **[draft 2]** The device certificate moved out of `sender` into the outer `fcert`. Friendship and workspace proofs stay inside the ciphertext, so the relay learns nothing about relationships.
- **[draft 2] Kinds:**
  - `msg`, `roster` and `idle` are session traffic, authorised by `mayExchange` against the roster for `(own, sid)`.
  - `unfriend` carries the unfriend JWS in `text`. It must be signed by `from` and name the recipient as `peer`, and needs no roster.
  - `sync` is accepted only from the recipient's own user (`from == to`), and needs no roster.
  - **[draft 2, D8]** `contact` delivers one friend invite, accept or unfriend between users who need not share a session.
    - **Shape:** `own` must equal `from`, and `sid` must be the reserved literal `~contact`. The sid `~contact` is rejected with any other kind, and kind `contact` is rejected with any other sid.
    - **Plaintext:** `text` must be exactly one compact JWS of `typ` `p2p-invite+jws`, `p2p-accept+jws` or `p2p-unfriend+jws`, at most 16 KiB. No free text, no `roster`, no `sender` proofs.
    - **Authorisation:** no roster or friendship is needed, only a valid `fcert` chain and the envelope signature. The replay window applies as usual, keyed `(fdid, from, "~contact")`.
    - **Checks on the object:**
      - It must be signed by a device of `from`.
      - An invite's `aud` must be the recipient or `*`, and the invite must be unexpired.
      - An accept's `inv` must match an outgoing invite this device stored. Otherwise it is ignored with reason `unknown-invite`.
      - An unfriend must name the recipient as `peer`.
    - **The receiver stores nothing.** The app decides:
      - invites are held for the user;
      - accepts that match this device's invite are adopted through `recordFriendship`;
      - unfriends are applied.
- **Replay protection:** **[draft 2, D6]** the receiver rejects:
  - `ts > now + 10 min` (future skew);
  - `ts < now - 24h - 10 min` (older than the relay's 24h store-and-replay window plus skew);
  - **[draft 2, D7]** a `seq` outside the sliding anti-replay window for `(fdid, own, sid)`. The window keeps the highest accepted seq `H` and a bitmap of the last `W = 512` seqs:
    - `seq > H` is accepted and slides the window;
    - `H - W < seq <= H` is accepted once, if its bit is unset, and rejected as `replayed-seq` if it is set;
    - `seq <= H - W` is rejected as `seq-too-old`;
  - a repeated `n` (LRU of the last 10k per device).

  The persisted window is what blocks replays inside the 24h window, and it tolerates reordered delivery within `W`. The nonce LRU is defence in depth: at 10k entries it may not span a full 24h for a very chatty sender. Draft 1's `|now - ts| > 10 min` would have dropped every relay-replayed envelope older than 10 min.

  **[review fix L1]** Draft 1's "gap under 1000" restart reset is removed: `H` only rises. Senders persist `seq`, and a reinstall gets a new `did`.
- **What the relay sees:** only the outer JWS (from, fdid, fcert, to, tdid, own, sid, seq, ts, kind, sizes).

## Authority HTTP (human SSO JWT unless noted)
- `POST /v1/p2p/devices`
  - Body: `{ "did", "spk", "kpk", "proof":"<p2p-devreg+jws over {did, spk, kpk, sub, nonce, iat}, signed with spk>" }`. The proof shows the device holds the private key.
  - Returns `{ "device":"<cert>", "workspace":"<attestation>" }`. Re-posting the same `did` renews it.
  - Device cap: 10 per user. PATs are allowed only when they carry scope `p2p:device`, for headless agents.
- `POST /v1/p2p/attest`: renews the workspace attestation and the device certificate for the caller's device. Body: `{did}`.
- `GET /v1/p2p/devices?user=<userId>`: the device certificates of `user`.
  - Returned **only** when the caller shares a workspace with them, or the caller presents a valid friendship or invite proof in the header `X-P2P-Proof`.
  - Otherwise it returns 404 with an identical body.
- `DELETE /v1/p2p/devices/{did}`: the caller's own device. It adds the device to the revocation list.
- `GET /v1/p2p/revocations`: public, returns the signed list.
- `GET /.well-known/p2p-jwks.json`: public.
- **Signing key:** a KMS-held asymmetric Ed25519 key, usable for signing only by the authority service.
  - For local dev and tests, a file-or-env Ed25519 key is used behind the same `Signer` interface.
  - The key id is the KMS key version resource name, hashed: `b64u(sha256(name))[:16]`.

---

## Draft 2 changes

- **D1. `fcert` in the outer payload** (resolves C2). The receiver verifies the sender's certificate before opening, and needs no directory lookup to receive. `plaintext.sender.device` is removed.
- **D2. `own` in the outer payload and the AAD** (resolves C9). A session is identified by `(own, sid)`. Rosters are looked up by `(own, sid)`, and a roster with `iss != own` is rejected. Draft 1's multi-owner `roster-conflict` heuristic is gone.
- **D3. Two-sided authorisation** (resolves C6). The viewer must independently satisfy (a), (b) or (c).
- **D4. Non-`msg` kinds** (resolves C5). `unfriend` carries its JWS in `text`, `sync` is accepted only from the same user, and `roster`/`idle` are authorised like `msg`.
- **D5. A single AAD form** (from C1). It is the fixed string, now including `own`.
- **D6. Late delivery** (from the relay build). The replay window accepts `ts` from 24h10m in the past up to 10 min in the future, so envelopes replayed from the relay's 24h store are accepted. Replays are blocked by the seq window (checked first) and then by the nonce LRU.
- **D7. Sliding anti-replay window** (re-review). A strict seq floor dropped reordered messages (8 then 7). It is replaced, per `(fdid, own, sid)`, by an IPsec/DTLS-style window: the highest seq `H` plus a 512-bit bitmap. Relays need not deliver in order.
- **D8. `kind: "contact"`** (Phase 4 needed it). It delivers invites, accepts and unfriends between users who share no session. Phase 4 had improvised `kind: "msg"` with sid `~contact`, which stock receivers reject, and which D8 now forbids. Details are under Kinds.
- **D9. `roster.org` needs the owner's attestation** (HIGH, found in a pre-release review). A roster's `org` used to grant workspace standing to anyone attested in that org, including the viewer, even though the owner picks `org` freely. So Mallory (evil.io) could sign `{vis:"workspace", org:"acme"}`, and acme members' devices accepted her messages (`owner`/`workspace`). Org-based rules now require a verified attestation showing the owner in `roster.org`, carried as `plaintext.ownerWorkspace`.

**Security-review fixes (pre-release, at c41ae23)**, also marked inline:
- **H1:** an unfriend burns the invite. The viewer's authorisation uses only its own stored friendships and unfriends.
- **M1:** replay check-and-record is atomic.
- **L1:** the seq restart rule is removed.
- **L2:** the Ed25519 strictness note is corrected (C11).
- **L4:** revocation-list freshness; friendships whose signer cert has expired are dropped.
- **L6:** JWS size caps and directory fsync.
- Explicit small-order key rejection for device certificates and devreg proofs.

**Re-review fixes (pre-release, at 953e0e9):**
- **H1 variant (medium):**
  - An unfriend also kills friendships built on any invite of the pair issued at or before it (C4).
  - `verifyIncoming` never stores friendships, whatever the kind. Stored friendships come only from the viewer's own explicit invite/accept flows (`recordFriendship`), which refuse an unfriended friendship.
  - Rosters are stored only after authorisation passes.
- **Lock races (low):**
  - The lockfile carries a random token and is removed only if it still matches.
  - A lock is broken only when its holder is gone: a dead pid on this host, or old age when the pid can't be checked.
  - Breaks are serialised and re-checked.
  - Holders refresh the lock's mtime (C7).
- **Reordering (medium, design):** D7.

Details are under C4, C7, C8, C11 and C13 below.

Final outer payload field order, as emitted by `packages/core`: `v, from, fdid, fcert, to, tdid, own, sid, seq, ts, n, epk, ct, kind`. Verifiers check the signature over the received bytes, so field order doesn't affect interop.

## Clarifications made while implementing `packages/core`

The draft 1 text was copied from the version agreed with the authority. The draft 2 edits above are marked inline. These are the places where the draft was ambiguous or incomplete, and the reading `packages/core` takes. Items that draft 2 resolved say so.

**C1. Envelope AAD.** Draft 1 gave two AADs. The core uses only the fixed string, which draft 2 adopts (D5). `|` is forbidden in `from`, `to`, `own` and `sid` so the string stays unambiguous. `n` and `epk` are not in the AAD; they are bound by the outer signature and by the KDF.

**C2. The sender certificate is needed before opening. Resolved by D1.** In draft 1 the certificate rode inside the ciphertext, but the static X25519 term needs the sender's `kpk` to decrypt. It is now the outer `fcert`.

**C3. `mayExchange` rule (c) precedence.** The rule reads as *sender ∈ parts* **and** (*a live friendship with `roster.iss`* **or** *an attestation that includes `roster.org`*). The other reading, (parts ∧ friendship) ∨ attestation, would let any workspace member post into a `private` roster, which would make `vis` meaningless.

**C4. Friendship validity.**
- Both signer certificates (the invite's and the accept's) must verify now: the authority's signature, unexpired, not revoked. Renewal keeps the same `did` and keys, so a long-lived friendship survives the 30-day certificate expiry. Revoking either signing device ends the friendship ("reject anything signed by a listed device").
- "Unexpired invite" is judged when the invite was accepted: `invite.iat - skew <= accept.iat < invite.exp`.
- **[H1, re-review]** An unfriend between a pair (from either side) ends a friendship of that pair when either:
  - it names that friendship's invite (`inv`). The accept's `iat` is not compared, because a re-signed accept for the same, still-unexpired invite would otherwise revive the friendship;
  - the friendship's invite was issued at or before the unfriend (`invite.iat <= unfriend.iat`), whoever issued it. Otherwise another invite still open at unfriend time (a shared `aud:"*"` code, or a second invite) could re-friend.

  Re-friending needs an invite issued after the unfriend.
- **[H1]** On the viewer's side only the viewer's stored friendships count. **[re-review]** `verifyIncoming` never stores a friendship: a proof carried by an envelope of any kind is evidence for that message's sender side only, never a grant. Friendships are stored only through the app's explicit flows, by calling `recordFriendship`:
  - right after this user accepts an invite;
  - when an accept arrives (for example as `result.friendship`) for an invite this user issued;
  - when this user's other devices sync one.

  `recordFriendship` refuses a friendship an unfriend has already ended (`unfriended`).
- **[L4]** Before a stored friendship is used it is re-verified: both signer certificates must still be valid (unexpired and not revoked). A friendship whose signer's certificate lapsed without renewal stops counting.
- For an `aud:"*"` invite, the first accepter a device records binds it. A friendship with the same `inv` but a different invitee is rejected (`invite-already-bound`).
- The invites, accepts and rosters that ride in the plaintext carry no certificates of their own. Their signers' certificates come from the sender's `fcert` (when the sender device signed them), the local cache, or the directory.

**C5. Non-`msg` kinds. Resolved by D4.**

**C6. Who can reach whom after an unfriend. Resolved by D3:** authorisation is two-sided. The viewer's standing comes from its own stored friendships and its own workspace attestation, which `verifyIncoming` takes as `ctx.self.workspace`. Sender failures are reported first (`not-participant`, `no-friendship`, `unfriended`). Viewer failures carry a `viewer-` prefix.

**C7. Replay.**
- **[D7]** The seq check is a sliding anti-replay window per `(fdid, own, sid)`: the highest accepted seq `H` plus a 512-bit bitmap, persisted as `{h, bits: b64u}`.
  - A seq above `H` is accepted and slides the window.
  - A seq within `W` below `H` is accepted once.
  - Anything at `H - W` or below is rejected (`seq-too-old`).
  - **[L1]** There is no restart reset. Senders must persist `seq` per `(fdid, tdid, own, sid)`, and a reinstall gets a new `did`.
- **[M1]** The check and the record are one atomic store operation (`TrustStore.admitReplay`). It runs once the sender's signature has verified, so only authentic sender traffic touches replay state. Of two concurrent deliveries of one envelope, exactly one passes.
  - `verifyIncoming` calls for the same sender device on the same store are serialised by a per-`fdid` lock.
  - The store merges replay records rather than overwriting them: nonces are unioned, and windows are OR-ed after aligning both to the larger `H`. The merge is commutative and idempotent.
- **[re-review] `FileTrustStore` lockfile.** Every read-modify-write holds `<dir>/.lock`, so several processes can share one directory without lost updates.
  - The lock is created exclusively and holds `{pid, host, token}`. Release removes it only if the token still matches. The holder refreshes its mtime every 5 s.
  - The lock appears with its content: the body is written to a temp file that is hard-linked to `<dir>/.lock` (a link never replaces an existing file). Created empty and then written, a process that exited in between left an empty lock that held every other process for 30 s. Where hard links aren't supported, the temp file is copied to `<dir>/.lock` exclusively (`COPYFILE_EXCL`), so the lock still appears with its body. An EEXIST for a lock that holds the creator's own body (a retransmitted request on NFS) means the lock is the creator's.
  - A lock is broken only when its holder is gone. On the same host that means its pid is dead (`process.kill(pid, 0)`). When the pid can't be checked (another host, or unreadable content, including an empty lock an older client left), it means the lock is older than 30 s. A shorter rule for empty locks would let a stalled creator, or a file server whose clock is behind, look dead while it holds the lock.
  - Breakers serialise on `<dir>/.lock.break` and re-read the lock before removing it, so a freshly acquired lock is never broken.
  - Residual risk: two cleaners can race to clear a breaker marker left by a crashed breaker. That needs a breaker crash in mid-break.
- Replay state is recorded even if the envelope is later refused by authorisation. That is harmless: it is the authentic sender's own envelope.
- Replay state is persisted, so a receiver restart does not reopen the window, and draft 1's "a restart resets the window to `ts`" no longer applies. **[D6]** The seq window is checked before the nonce LRU, so a duplicate is reported as `replayed-seq`.

**C8. Time.**
- Lifetimes are enforced as maxima: certificates at most 30 days, attestations at most 24 hours, invites at most 14 days. `exp` is exclusive.
- An `iat` up to 300 s in the future is tolerated to allow for clock skew. Envelope `ts` uses the D6 window: from 24h10m in the past to 10 min in the future.
- **[L4] Revocation-list freshness.** Every successful poll records `fetchedAt`, including a re-poll that returns the same list.
  - When the list was last polled more than 1 h ago, `verifyIncoming` calls `onWarning`.
  - After more than 24 h, or with no list at all, it fails closed (`revocations-stale`).
  - Both thresholds are configurable (`revocationWarnAgeMs`, `revocationMaxAgeMs`).

**C9. Session ids are not owner-scoped. Resolved by D2.**

**C10. Rosters at the same version.** Two different rosters with the same `(iss, sid, ver)` are rejected (`roster-conflict`). This is an equivocation check, not draft 1's multi-owner heuristic. A presented roster older than the one held is rejected (`stale-roster`), not silently replaced by the newer one.

**C11. JWS details.**
- Signers emit the header `{"alg":"EdDSA","typ":…,"kid":…}`. Verifiers accept any field order, because they verify the received bytes, but reject `crit`.
- `typ` is checked before any key lookup, so a confused object is reported as `typ-mismatch`.
- **[L2]** Ed25519 verification uses noble with `zip215: false`. That check is cofactored, and it rejects non-canonical and small-order `A` and `R` encodings, which makes the client **stricter than Go's `crypto/ed25519`**. A signature Go accepts under a weak key can fail here. The Go authority is adding small-order `spk` rejection at registration, so honest keys never hit the difference.
- base64url decoding rejects padding and non-canonical trailing bits.
- **[L6]** Size caps: a non-envelope JWS may be at most 16 KiB, matching Go. An envelope may be at most 64 KiB, enforced when sealing and when receiving.

**C12. Device registration.** The `p2p-devreg+jws` proof has `kid = deviceId`. Its `nonce` is 16 random bytes in b64u unless the server supplies one. Under a host keychain, the secret for account `<userId>/<deviceId>` (service `ix-p2p`) is `b64u(ed25519_seed(32) || x25519_secret(32))`.

**C13. Small-order keys.** Before any signature check, device certificates and devreg proofs must carry:
- an `spk` that decodes canonically to a torsion-free Ed25519 point of large order (the identity point, for example, is rejected);
- a `kpk` that is not a low-order X25519 point (for example `u = 1`).

The rejection reason is `small-order-key`, which corresponds to Go's `small_order_key`.

**C14. Atomic file writes.** `FileTrustStore` writes to a 0600 temp file, fsyncs it, renames it over the target, then fsyncs the directory, so the rename itself survives a crash.
