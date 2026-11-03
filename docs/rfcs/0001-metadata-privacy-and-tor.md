# RFC 0001: Metadata privacy and optional Tor transport

| | |
|---|---|
| **Status** | Accepted (2026-10-23; all eight decisions in §12.1 taken as recommended). Nothing here is implemented yet: each phase in §13 lands its own spec text in protocol.md. |
| **Date** | 2026-10-22 |
| **Applies to** | [protocol.md](../protocol.md) v3 draft 3, as amendments gated on status caps, the same way as the status-caps amendment (footprint P0) |
| **Comes after** | the footprint work (P0–P1 shipped; later footprint phases come first) |
| **Approved scope** | CEO-approved privacy phase: (1) metadata privacy, (2) optional Tor transport, (3) bring-your-own egress for agents' web access |

Words in capitals (MUST, SHOULD, MAY) are used as in RFC 2119. Section signs (§) without a file name point into [protocol.md](../protocol.md).

## 1. Summary

Relays already see only ciphertext. They still see a lot of metadata: who sends to whom (by userId and device), which session a message belongs to, how many messages it carries, how big each one is, when it was sent, from which IP address, and, through capabilities, the whole friend graph in pseudonymous form (§5.3, §7).

This RFC proposes five optional mechanisms that shrink that metadata, and one boundary that stays fixed:

1. **Sealed sender.** The sending device, its user, the session, the sequence number and the kind move inside an extra layer of encryption. The relay admits the send with a **sealed delivery token** (a single-purpose ticket the recipient issued) or a `sub:"*"` capability, rather than by the sender's signature. Spam resistance comes from the recipient's own token budget, from PoW on first contact, and from per-network limits.
2. **Size padding.** Sealed envelopes are padded to one of six fixed sizes (2, 4, 8, 16, 32 and 64 KiB).
3. **Timing cover traffic** (opt-in). Either random send delays, or constant-rate sending with dummy loop messages to the user's own mailbox.
4. **Two-hop relay forwarding** (opt-in). The client hands a sealed send to an *entry* relay, which forwards it to the recipient's *mailbox* relay. This is the same shape as Oblivious HTTP: the entry relay sees the sender's network address but not the recipient, and the mailbox relay sees the recipient but not the sender's address. Forwarding goes **only from relay to relay**.
5. **Tor transport** (opt-in, never default). The client reaches relays through a local Tor SOCKS proxy (`"transport": "tor"`). A relay MAY also offer a `.onion` address.

The fixed boundary: **a relay never acts as an exit to the open web.** Agents that want private web access bring their own egress (Tor, a VPN or a corporate proxy), configured in the agent runtime. Relays never see that traffic (§8).

None of this changes the cryptography of the inner envelope, its authorisation rules (§4.2) or its replay rules (§4.4). The recipient still verifies every envelope exactly as today, once it has removed the sealed layer.

## 2. Motivation

### 2.1 What a relay sees today

From protocol.md §5 and the relay code (`packages/relay/src/server.ts`, `onSend`):

| Data | Where the relay sees it | What it reveals |
|---|---|---|
| `from`, `fdid`, `fcert` | outer envelope fields, verified at the relay | the sending user and device |
| `to`, `tdid` | `send` frame and outer envelope | the receiving user and device |
| `own`, `sid`, `seq` | outer envelope fields | which session a message belongs to, and how many messages each session has sent |
| `ts`, `kind` | outer envelope fields | when a message was written, and whether it is a message, a status, a contact, circle traffic or an extension |
| size | the envelope's length | which kind of thing it is (a status is about 2 KiB, a circle bundle is much larger) |
| arrival time | the relay's clock | activity patterns, and replies matched to the messages they answer |
| the cap's `iss`/`sub` | a cap presented with each send | who may reach whom, even before any message (the friend and co-member graph) |
| the authenticated connection | `auth` binds a connection to `(iss, did)` | which user is online, from which IP, and for how long |
| the source IP | the TCP connection (or `X-Forwarded-For`) | the network location of both sender and recipient |

Relays are deliberately simple and anyone can run one (§5.1). That is good for resilience, but it means the metadata goes to operators the user may know nothing about. The relay software's privacy promise ([run-a-relay.md](../run-a-relay.md), "The privacy promise") limits what *honest* relay software stores. It cannot limit what a modified relay, or the host underneath it, records.

### 2.2 Why it matters for this network

- **Agent coordination exposes work patterns.** Statuses go out every 60 s per session (§4.3). A relay can see when someone's agents are busy, how many sessions they run, who they coordinate with, and the shape of a team, all without decrypting anything.
- **The friend graph is commercially sensitive.** Who is coordinating with whom on what can reveal hiring, acquisitions and incidents.
- **Volunteer relays are a stated goal.** If users can rely on relays learning less, they need less trust in relay operators. That is what makes an open relay network workable.

## 3. Goals and non-goals

### 3.1 Goals

- **G1. Sealed sender:** a relay that stores or forwards a sealed envelope cannot learn the sending user, device or session from protocol data.
- **G2. Spam resistance holds without sender identity:** every sealed send is admitted by something the recipient issued (a token or a `sub:"*"` cap), and first contact still costs PoW and is still rate-limited.
- **G3. Size padding:** within a bucket, sizes reveal nothing.
- **G4. Optional timing protection:** users who choose it can hide *when* they send, at a bandwidth cost they can see.
- **G5. Optional network-location protection:** users who choose it can keep their mailbox relay from learning their IP address, through two-hop forwarding or through Tor.
- **G6. Compatibility:** every mechanism is cap-gated and falls back cleanly. Clients and relays that predate it keep working, and nothing changes the outer envelope that older software verifies.
- **G7. An honest threat model:** for each option, it is written down what a single relay, colluding relays and a global passive adversary still learn (§4).

### 3.2 Non-goals

- **Relays as exits to the open web.** Never, in any mode (§8.1).
- **Defeating a global passive adversary by default.** Without a real mixnet (with delays and heavy cover traffic), an observer who sees every link can correlate timing. We give users partial tools and state the limits (§4.4).
- **Hiding the recipient from its own mailbox relay.** Mailboxes are keyed by `(userId, did)` (§5.2). Hiding the recipient would need private information retrieval or broadcast, which this RFC considers and rejects (§11).
- **Hiding that someone uses Peer2Peer.** Tor (or the user's VPN) can hide relay connections from a local network observer. Hiding it is not a protocol goal.
- **Hiding identity documents.** They are public by design (§5.6).
- **Making Tor required, or the default.** Tor is strictly opt-in (§7).
- **Changing what agent runtimes do on the web.** §8 is configuration and documentation of the user's own agent, not a feature of the protocol.
- **Deniability.** Inner envelopes stay signed by the sender's device, so the recipient can still prove who sent a message. Sealed sender hides the sender from relays, not from the recipient.

## 4. Threat model

### 4.1 Adversaries

| Id | Adversary | Capabilities |
|---|---|---|
| **R1** | **A single relay**, honest-but-curious or actively malicious | sees everything that reaches it (connections, IPs, frames, timing); can log, delay, drop, reorder or replay; cannot break TLS to other hosts or the cryptography |
| **R2** | **Colluding relays**: every relay a pair of users uses, or the entry and mailbox relays of a two-hop route | pools everything they see; correlates by timing across relays |
| **GPA** | **A global passive adversary** | sees every network link's packets, sizes and timing, but not inside TLS or Tor encryption; does not run relays (if it also runs them, it is GPA plus R2) |
| **L** | **A local network observer** (ISP, Wi-Fi, employer) | sees the user's own link only |
| **S** | **A spammer** | holds many cheap identities; may hold a token or cap leaked to it; may run relays |
| **A** | **An abusive automated agent** | wants free egress, anonymity for scraping or attacks, or a way into the operator's network |

### 4.2 What each party learns, option by option

"Mailbox relay" means the relay that holds the recipient's mailbox. In each cell, ✗ means the party learns this, ◐ partly or probabilistically, and ✓ that it is protected.

**Sender identity (who sent this envelope):**

| Option | Single relay | Colluding relays | GPA |
|---|---|---|---|
| Today | ✗ outer `from`/`fdid` | ✗ | ◐ by timing (the sender's upload matches the recipient's download) |
| Sealed, direct | ◐ not in protocol data, but the relay sees the sender's IP. If the same IP also holds the sender's own authenticated mailbox connection on that relay, or ever did, re-identifying the sender is trivial. | ◐ same, across relays | ◐ unchanged |
| Sealed over Tor (a separate circuit from the mailbox connection) | ◐ only statistically: a reply that arrives seconds after a delivery to someone, repeated over time (statistical disclosure, as in Martiny et al. on Signal, NDSS 2021) | ◐ same, with more observations | ◐ Tor gives no protection against end-to-end timing correlation |
| Sealed, two-hop | ✓ entry relay: sees the sender's IP but not the recipient. Mailbox relay: sees the recipient but not the sender's IP. Statistical disclosure remains (as above). | ✗ if the entry and mailbox relays collude (or are one operator), they rejoin both halves | ◐ no mixing, so timing correlates across the hop |
| + constant-rate cover | ◐ the sender's upload pattern no longer shows when it really sends | ◐ | ◐ sender side hidden; recipient downloads still bursty |

**Recipient identity:** the mailbox relay always learns it (non-goal, §3.2). Under two-hop, the entry relay does not. A GPA sees the recipient's download from its mailbox relay.

**Session, sequence and kind (`own`, `sid`, `seq`, `kind`, `ts`):** ✗ today; ✓ under sealed sender (all inside the sealed layer), for every adversary. Only the bucketed size and the arrival time remain.

**Message size:** ✗ today (exact). With padding: ◐ the bucket only, about 2.6 bits per envelope. An envelope above 32 KiB still stands out.

**Linking sends together:** under sealed sender, sends that spend the same multi-use token are linkable by the mailbox relay (up to `uses` sends, §5.1.3). Sends with different tokens are linkable only by IP, connection or timing.

**The friend graph:**
- Today, caps reveal `iss` and `sub` with every send.
- Under sealed sender with tokens, the relay learns only how many tokens each recipient registers and how fast they are spent. The token registration batches a recipient makes are shuffled across peers (§5.1.3), so the relay doesn't learn per-peer groups, except at revocation.
- Unsealed fallbacks (first contact, peers on old clients) still reveal pairs.

**Online presence and network location:**
- The mailbox relay always sees when a recipient device is connected.
- Under Tor, it sees a Tor exit or an onion circuit instead of the user's IP.
- Under two-hop alone, it still sees the recipient's own IP on the recipient's mailbox connection, because receiving through a hop is out of scope (§12, Q-T4).

### 4.3 What spam and abuse look like under each option

- **Sealed sender:**
  - A spammer needs a token, or a `sub:"*"` cap, issued by the recipient.
  - A token holder can send at most what the tokens allow, and only until the recipient revokes them.
  - A leaked `sub:"*"` contact cap is bounded by `uses`, its PoW and the per-cap rate (§5.1.5).
  - A leaked circle join cap is bounded the way it is today (§5.3 M3): spam, not access, and fixed by re-signing the join.
- **Revoked devices:** the relay can no longer check the sender's device against the allowlist (rule 6), because the device certificate is sealed. A revoked device that still holds tokens can therefore get envelopes stored. The recipient rejects them on opening (§4.1), and tokens live at most 7 days. That cost is accepted.
- **Two-hop:** entry relays forward only for their own authenticated users (§6.4), so a stranger cannot use a relay as an anonymous entry. Mailbox relays still need a token or cap for each forwarded send.
- **Agents (A):** no mode gives any client a path to an arbitrary host (§8.1).

### 4.4 What we are honest about

- **Sealed sender without network anonymity is a weak guarantee against an operator who logs IPs.** It keeps sender identity out of protocol fields, stored data, logs, metrics and breach dumps, and it raises the bar for an operator to *systematic* traffic analysis. It does not stop an operator determined to re-identify senders by IP. The real guarantee needs either Tor (§7) or two-hop through an independent operator (§6).
- **Two-hop is only as good as operator diversity.** If the public relay holds most mailboxes, and also serves as the entry for most users, one operator sees both halves. Clients refuse a route whose entry and mailbox relays share a registrable domain or a declared operator (§6.5), but nobody can prove two relays are run by different people.
- **Nothing here defeats a GPA.** Tor and two-hop are low-latency and do no mixing. Constant-rate cover hides *when a sender sends*, but not *when a recipient receives*. Real GPA resistance needs a mixnet (Loopix and Nym style, with per-hop delays measured in seconds and continuous cover traffic in both directions). That doesn't fit 60-second presence and interactive agent chat at a bandwidth cost laptops and phones accept (§11).
- **Statistical disclosure works on everything here given enough rounds.** Long-running relationships with regular replies leak over time. Ephemeral sender keys or per-conversation identities would help, and are left open (§12).

## 5. Design: sealed sender, padding and cover traffic

### 5.1 Sealed sender

#### 5.1.1 The sealed wrapper

A sealed envelope is the ordinary §4.1 envelope JWS, unchanged and still signed by the sender's device, wrapped in one more layer of encryption to the recipient device's `kpk`:

```
plaintext P = type (1 byte) || L (4 bytes, big-endian) || inner (L bytes) || zero padding up to the bucket size B (§5.2)
  type  = 0x01 for an envelope, 0x00 for cover traffic (§5.3; L = 0, no inner)
  inner = the UTF-8 bytes of the §4.1 envelope JWS, with env.to == to and env.tdid == tdid

epk, esk = a fresh X25519 key pair
shared   = X25519(esk, kpk of tdid)              (kpk from the recipient's device certificate, §2.3)
key      = HKDF-SHA256(ikm = shared, salt = epk || kpk, info = "p2p/v3/sealed|" + to + "|" + tdid, 32)
nonce    = 24 random bytes
aad      = "p2p/v3/sealed|" + to + "|" + tdid + "|" + B
sealed   = b64u(epk || nonce || XChaCha20-Poly1305(key, nonce, aad, P))
```

- **Primitives:** only those of §1, so `@peer2peer/core` adds no dependency.
- **The inner envelope carries `fcert`.** The recipient learns and verifies the sender exactly as it does today. This is the analogue of Signal's sender certificate, except that ours is the sender's own device certificate, not one issued by a server.
- **What a relay holds:** `to`, `tdid`, and an opaque blob whose length is one of six values. The sender's userId, device, certificate, session, sequence number, timestamp and kind are all inside.
- **Inner envelopes are at most 65,531 bytes** (64 KiB minus the 5 header bytes), so they fit the top bucket. A larger envelope goes unsealed. Circle bundles are already split across envelopes (§4.3), and senders splitting at 60 KiB keeps them sealable.
- **Recipients MUST check** that the padding bytes are zero, that `type` is 0x00 or 0x01, and that `inner.to == to` and `inner.tdid == tdid`. Then they run every §4.1 check, §4.2 and §4.4 on the inner envelope as if it had arrived unsealed.

#### 5.1.2 Sending without saying who you are

A sealed send is a new frame. It is the only send frame a relay accepts **without authentication**:

```
{"t":"send-sealed","id":"<client msg id>","to":"<recipient userId>","tdid":"<did>","sealed":"<b64u>",
 "tok":"<b64u 16-byte token>"}                                  admitted by a delivery token (§5.1.3), or
 "cap":"<p2p-cap+jws with sub:"*">","pow":"<b64u nonce>"?}      admitted by a sub:"*" cap (§5.1.5)
```

- **Use a separate connection.** A client MUST NOT send `send-sealed` on a connection where it has authenticated. If it did, the connection's `(iss, did)` binding would name the sender.
  - The client keeps a separate, **unauthenticated sending connection** per relay.
  - It reopens that connection at least every 10 minutes and after every idle gap of more than 60 s, so one connection doesn't link a whole day's sends.
  - Under Tor, the sending connection uses a different circuit from the mailbox connection (§7.3).
- **Relay connection rules:** today a connection that hasn't authenticated may only do `link-*` and `invite-get`, and it is closed after `unauthTimeoutSec`. A relay advertising `sealed.v1` also accepts `send-sealed` on it, with its own limits (§5.1.6), and resets the unauthenticated timeout on each accepted sealed send, up to a cap of 10 minutes.
- **Replies:** `{"t":"sent","id"}`, or `{"t":"error","id","code"}` with the existing codes. Every admission failure (unknown token, spent token, revoked token, wrong mailbox, bad cap) is the one `undeliverable` code, as in §5.4.
- **Unknown mailboxes:** a send to a mailbox the relay doesn't know is answered `sent` and dropped, as for a cap-less contact (§5.4 L2). This is checked after the token check, so a token can't be used to probe whether a mailbox exists.

#### 5.1.3 Sealed delivery tokens

A **sealed delivery token** is 16 random bytes `t` that a recipient registers at one of its relays, and hands, end-to-end encrypted, to one peer. It is the recipient's permission for "whoever holds this" to put up to `uses` sealed envelopes into the recipient's mailboxes on that one relay before `exp`.

**Register** (authenticated, from a device of the recipient `U`, never over a restricted connection):
```
{"t":"tok-reg","toks":[{"h":"<b64u H("p2p/v3/sdt|" || t)>","exp":<s>,"uses":<int 1..1024>}, ... ≤ 256]}
→ {"t":"ok","n":<accepted>}
```
- The relay stores `(U, h) → {exp, usesLeft}`.
- **Limits:** `exp ≤ now + 7 d` (the store's lifetime, §5.4). At most `limits.tokensPerIss` live tokens per user (default 20,000), and `limits.tokRegPerIssPerHour` registrations an hour.
- **A token is good for every device mailbox of `U`** on that relay. Tokens never name a device or a peer.
- **The relay stores only `h`.** A copy of the database can't be used to spend tokens.

**Hand out** (end-to-end encrypted, recipient to peer, a new kind, §5.1.4):
- The recipient generates **different tokens for each relay**, so colluding relays can't link sends by token.
- Each peer gets its own tokens, so the recipient can revoke them per peer.
- The recipient registers each day's tokens for **all** peers in **one shuffled batch** per relay, so the relay can't group tokens by peer.

**Spend:**
- The sender presents `t` itself in `tok`.
- The relay computes `h`, checks that `(to, h)` is registered, unexpired, not revoked and has `usesLeft > 0`, and decrements `usesLeft` (the same counter machinery as cap `uses` today, `store.useCap`).
- The relay remembers `H(sealed)` for the token's lifetime and answers a repeated blob `sent` without storing it again. This replaces today's `env.from == auth.iss` rule, which kept a captured envelope from being replayed into a relay.
- **On delivery,** the relay tells the recipient which token was spent (`tok: h`, §5.1.7). The recipient can then tell which peer a token was issued to, and spot a leaked one.

**Revoke** (authenticated, from a device of `U`):
```
{"t":"tok-revoke","hs":["<b64u h>", ...≤ 1024]}
```
- **Recipients revoke a peer's unspent tokens** at every relay on unfriend, block, or removal from a circle, and when a token is spent by someone other than the peer it was issued to (below).
- **Revoking reveals that group.** Revoking reveals to the relay that those tokens were issued together. That is the one moment the relay learns a per-peer group. Tokens expire within 7 days anyway, so a client MAY skip revocation for a peer whose remaining tokens expire within 24 h.

**How linkable sends are depends on `uses`.** Every send that spends one token is linkable by the mailbox relay:
- `uses = 1` makes every send unlinkable by token, at the price of one token (16 bytes to hand out, about 48 bytes stored at the relay) per send;
- larger `uses` costs less and links more.

**The default is `uses = 64` (decided, Q-C7), with the peer spending a token until it runs out.** At one status a minute, that links about an hour of one session's statuses to one pseudonym, and never ties it to a userId. Costs are in §10.

**Issuance budget:** per peer and per relay, the recipient issues enough tokens for `limits.sends` at the expected rate. By default that is 32 tokens × 64 uses a day, about 2,000 sends, more than one session's statuses (1,440 a day) plus messages.
- A sender that runs low asks for more (`tokens` `want`, §5.1.4).
- The recipient MAY refuse, and a recipient under spam lowers the budget.
- With no tokens left, the sender falls back to unsealed with its cap, or waits in strict mode (§9.3).

**Who gets tokens:**
- friends;
- the user's own other devices (through `sync`, so they can send each other sealed traffic and loop cover traffic, §5.3);
- circle co-members lazily: only peers who sent this user something authorised (§4.2) in the last 7 days, at most `tokenPeers` of them (default 200).

**Co-members who have no tokens yet** can still send sealed with the member's join cap (§5.1.5), so issuance stays linear in actual conversations rather than quadratic in circle size.

#### 5.1.4 New end-to-end kind: `tokens`

| kind | sid | authorised by | plaintext |
|---|---|---|---|
| `tokens` | `~tokens` | `from == to` (own devices), or the sender is a friend, or stands in a circle with the recipient (§3.3) | `{grant:[{relay:"<canonical URL>", t:["<b64u 16B>", ...≤ 256], exp:<s>, uses:<int>}, ...≤ 5]}` **or** `{want:{relay:"<canonical URL>", n:<int ≤ 64>}}` |

- Sent only to a device whose latest status advertised `sealed.v1` (§9.1), because clients that predate it reject the unknown kind.
- The plaintext is strict like every other kind's (§4.3).
- The `~tokens` sid is reserved like `~contact` and `~circle`.
- `tokens` envelopes themselves go sealed whenever the sender holds a token or cap for the recipient. A user's first grant to a new friend goes unsealed with the friend cap.

#### 5.1.5 Sealed sends with a `sub:"*"` cap (contact and circles)

Two kinds of capability already name no sender (§5.3). Either can admit a sealed send:

- **Invite contact caps** (`sub:"*"`, `kinds:["contact"]`, usually with `uses`): this is **sealed first contact**.
  - The relay checks the cap exactly as today: valid, `iss == to`, the relay is listed, unexpired, not revoked, `uses` per relay.
  - It requires `pow` over the **sealed bytes** when `hello.pow > 0`: `H(sealed_bytes || pow)` has that many leading zero bits.
  - It applies the contact limits per source network and per `(capid, to)` instead of per sender userId (defaults: 120/h per network, as today, and 3/h per cap and recipient).
  - **The relay can no longer check `kinds`** (the kind is sealed), so the **recipient enforces it**: an envelope admitted by a `kinds:["contact"]` cap (`via:"cap"` on delivery, §5.1.7) whose inner kind isn't `contact` is dropped. The cost of a leaked contact cap stays bounded by `uses`, PoW and the per-cap rate.
- **Circle join caps** (`sub:"*"`, `kinds:["*"]`): these are shared by every co-member. They work like Signal's per-recipient "unidentified access key", with a per-cap rate limit at the relay (`limits.sealedPerCapPerMinute`, default 120). A co-member who abuses one gets the same remedy as today: the member re-signs its join with a fresh cap and revokes the old one (§5.3 M3, P2).
- **A cap with `sub:"<userId>"` names the sender,** so it is never used for a sealed send.

**Cold contact (no ticket at all) stays unsealed:** a stranger with no invite cap sends an ordinary cap-less `contact` with PoW (§5.4), which reveals the sender to the relay. Allowing anonymous cold contact admitted only by PoW would make the sealed path a spam firehose with nothing to revoke. This is question Q-C3 in §12.

#### 5.1.6 Rate limits and storage on the sealed path

| Today (unsealed) | Sealed equivalent |
|---|---|
| 120 sends/min per `env.from` | the token budget the recipient chose (`uses` × tokens), plus `limits.sealedPerCapPerMinute` for cap-admitted sends |
| per-connection and per-IP send bytes (`sendBytesConn`, `sendBytesIp`) | unchanged, applied to the unauthenticated sending connection's IP. Under two-hop, applied per **entry peer** with a larger peer budget (§6.4). |
| per-source accepted bytes (`sourceAccepted`) | unchanged (per IP, or per entry peer) |
| contact limits per sender, per pair, per IP | per network, per `(capid, to)` (§5.1.5) |
| PoW on cap-less contact | PoW on cap-admitted sealed contact; none on token sends (the token is the ticket) |
| none | **per-recipient sealed inbound cap**: `limits.sealedInPerIssPerMinute` (default 600). A token holder who floods can only fill the recipient's sealed budget. That is a denial of service against that one recipient, ended by revoking the holder's tokens. |

**The store:**
- **Unchanged:** the 7-day lifetime, delete on ack, mailbox caps (10,000 envelopes and 64 MiB) and eviction order.
- **Source-first eviction** (the in-memory keyed `srcTag`) is keyed by the token hash `h` (or the `capid`) for sealed envelopes, instead of by IP. A flooder's own envelopes go first, even when many users share an entry relay or a Tor exit.

#### 5.1.7 Delivering sealed envelopes

```
{"t":"env","rid":"<relay id>","sealed":"<b64u>","tok":"<b64u h>"?,"via":"tok"|"cap"}
```

- **Opting in:** a relay delivers sealed frames only to a connection that opted in with `{"t":"recv-sealed"}` after `auth`. Until then they stay stored. This stops a relay from pushing frames a pre-RFC client can't parse and would never ack. A client that registers tokens or advertises `sealed.v1` sends `recv-sealed` on every mailbox connection.
- **`caught-up` (§5.4):** sealed envelopes count toward a connection's `caught-up` only once it has opted in. A client that opts in sends `recv-sealed` straight after `ok`, and the relay sends `caught-up` after the stored sealed envelopes as well as the plain ones, so a short-lived command doesn't stop listening before its sealed mail arrives.
- **Acks** are unchanged (`{"t":"ack","rids"}`).
- **Leaked tokens:** a sealed envelope whose inner `from` isn't the peer the token was issued to means the token leaked or was shared. The client still judges the envelope only by §4.2. It also revokes the rest of that peer's tokens and tells its user (`"tokens issued to <peer> were used by <sender>"`).

#### 5.1.8 How sealed sender fits the existing auth and spam model

| Existing mechanism | Under this RFC |
|---|---|
| **Device-signature auth to the relay** (§5.2) | Still required for receiving (the mailbox connection), publishing identity documents, registering and revoking tokens, `link-open` and `invite-put`. **Not** used for sealed sends, which travel on an unauthenticated connection. |
| **Mailbox capabilities bound to relay and kind** (§5.3) | Still issued and used for unsealed sends, exactly as today. For sealed sends, a token takes the cap's place at the relay. Tokens are bound to **one relay** (issued per relay) and **one recipient**. They are **not bound to a kind**, because the relay can't see the kind; the recipient's authorisation (§4.2) is what limits kinds. `sub:"*"` caps admit sealed sends, with kind enforcement moved to the recipient (§5.1.5). Unfriend, block and removal revoke tokens as well as caps. |
| **PoW on first contact** (§5.5) | Unchanged for cap-less contact, which stays unsealed. Required for sealed contact admitted by a contact cap, computed over the sealed bytes. |
| **Rate limits** | Per-sender limits become per-ticket limits (token `uses`, per-cap rate) plus a per-recipient sealed inbound cap. Per-network limits stay (§5.1.6). |
| **The 7-day store** | Unchanged. Tokens live at most 7 days, so a token never outlives the envelopes it admits, and replay dedup only needs to last as long as a token. |
| **Relay-side rule 6 for the sender** | Lost for sealed sends (the certificate is sealed). The recipient still applies it on opening. The cost is bounded by token lifetime and budget (§4.3). |
| **Uniform `undeliverable`, and silent drops to unknown mailboxes** | Kept. A token can't be used to probe whether a mailbox exists (§5.1.2). |

#### 5.1.9 Lessons from Signal

- **Signal's sealed sender (2018):** the sender's identity rides inside the encryption as a short-lived certificate the server issued. Delivery is admitted by a 96-bit *unidentified access key* derived from the recipient's profile key and shared with all contacts, with an opt-in "allow from anyone" mode, and abuse is handled with rate limits by IP.
  - **What we take:** the identity moves inside the encryption, and an admission ticket replaces identity at the server.
  - **What we change:** one shared key per recipient means one leaked or abusive contact forces a rotation for everyone, and the server can't rate-limit per contact. Per-peer, per-relay, multi-use tokens keep targeted revocation and per-sender budgets, at the cost of the bounded linkability set by `uses`.
- **Martiny et al., "Improving Signal's Sealed Sender" (NDSS 2021):** delivery receipts and replies let a server deanonymize sealed senders through statistical disclosure, often in a handful of messages.
  - **What we take:** §4.4 states this plainly. Our statuses are periodic and so give the same signal. Constant-rate cover (§5.3) and Tor or two-hop dampen it but don't remove it.
  - **Left open (Q-T2):** the paper's fix, ephemeral per-conversation identities.
- **Signal's group send endorsements (2024)** use anonymous credentials (zkgroup) so a sender can prove group membership for a multi-recipient sealed send without revealing which member it is.
  - Anonymous credentials (blind RSA, RFC 9474; VOPRF and Privacy Pass, RFC 9497 and RFC 9576–9578) would give single-use unlinkability at a lower distribution cost than `uses = 1` tokens.
  - We defer them (§11) because they add new cryptography and verification cost at relays.
  - The token frame is designed so a later `tok` format can carry a credential instead.

### 5.2 Size padding

Padding is applied to the sealed plaintext `P` (§5.1.1). The bucket `B` is the smallest of:

| Bucket | 2 KiB | 4 KiB | 8 KiB | 16 KiB | 32 KiB | 64 KiB |
|---|---|---|---|---|---|---|
| Typical contents | short `msg`, `idle`, `tokens` | `status` (about 2 KiB today, more with `agents`), `roster` | long `msg`, `contact` with an invite and document | larger statuses with files and agents | circle bundles, `x:` subgraphs | anything up to 65,531 bytes |

- **Every sealed envelope is padded.** There is no unpadded sealed form, so padding needs no separate cap.
- The wire size of a sealed frame is fixed per bucket: `b64u(32 + 24 + B + 16)`.
- **Why six power-of-two buckets** and not Padmé, which caps overhead at 12% but leaks O(log log n) bits per size: with only six sizes, an envelope leaks at most log₂ 6 ≈ 2.6 bits, at an average overhead of roughly 1.3–1.5× and a worst case of 2× (§10).
- **Unsealed envelopes are not padded.** Padding them would need a field in each kind's strict plaintext (§4.3) and a cap per kind. Sealed sender is the privacy path; unsealed is the compatibility path.
- **Relay frames that carry sealed envelopes** (`send-sealed`, `env` with `sealed`, `fwd`) carry no other variable-length field besides `tok` and `cap`, which are fixed-size or the same size on every send.

### 5.3 Timing cover traffic (optional)

A client setting, `"cover"`, with three values:

| Mode | What the client does | Hides | Cost |
|---|---|---|---|
| `off` (default) | nothing | nothing | none |
| `jitter` | delays each non-interactive sealed send (statuses, `tokens`, `roster`, `sync`) by a uniform random 0–`jitterSec` (default 20 s); interactive `msg` sends go at once | exact timing of state changes; correlation of statuses across a user's sessions | no bandwidth; up to 20 s of status latency, within the 150 s liveness window (§4.3) |
| `constant` | sends exactly one sealed envelope per slot (default every 15 s, with ±20% jitter) on each relay's sending connection. Real sends wait for the next slot; empty slots carry a **loop dummy** (`type = 0x00`, a 4 KiB bucket) sealed to one of the user's own devices with a self-issued token. | *when* this user sends, as seen by the sending relay, the entry relay or a GPA on the sender's link | bandwidth (§10); up to one slot of latency per send; queued sends past one per slot wait longer |

- **Dummies look like real sends.** They are sealed, padded and token-admitted exactly like real traffic. The relay can't tell them apart from a real send (it can't see the sender), and the user's own device drops them on opening. Like Loopix's loop cover traffic, they also let the client notice a relay that delays or drops traffic selectively: a loop that doesn't come back within 2 slots is counted, and `p2p doctor` reports it.
- **Under two-hop,** dummies take the same route as real sends.
- **Honest limits:**
  - `constant` hides the sender's side only.
  - Downloads to the recipient are still visible at the moment of delivery.
  - Hiding them too would need recipients to receive at a constant rate (dummy deliveries from the relay), which the relay would have to generate. That would let a relay tell real traffic from cover. It is deferred as Q-T3.
  - Cover traffic does nothing against statistical disclosure over long periods unless it runs all the time.

## 6. Design: two-hop relay forwarding (optional)

### 6.1 Shape

```
client ──TLS──▶ entry relay A ──TLS──▶ mailbox relay B ──▶ recipient's mailbox
         (sees the client's IP,      (sees A, `to`, the token,
          that B is the target,       the sealed blob; not the
          a fixed-size blob)          client's IP)
```

This is the Oblivious HTTP split (RFC 9458): a relay that knows who but not where, and a gateway that knows where but not who, with the payload encrypted to the gateway. Here both roles are Peer2Peer relays, and the payload is a `send-sealed` frame.

### 6.2 Forwarding keys

Each relay that supports forwarding has an X25519 **forwarding key**, published (and rotated at least every 30 days) in:
- `/.well-known/p2p-relay.json`: `"forward":{"kid":"<b64u 8B>","pub":"<b64u x25519>","exp":<s>}`;
- `hello`: the same object under `"forward"`.

**Fetching it:** the client fetches B's key from B's well-known document **directly over TLS** (or over Tor), and caches it until `exp`.
- TLS authenticates the key to B's canonical host, so A can't substitute its own.
- The single fetch tells B only that some IP is interested in its key. It happens long before, and independently of, any send.
- A relay keeps the previous key valid for 7 days after rotating.

### 6.3 Wire

**Client to A**, on A's authenticated **mailbox** connection. A needs to know whose forwarding it carries (§6.4), and A doesn't learn the recipient.
```
{"t":"fwd","id":"<client msg id>","relay":"<canonical URL of B>","kid":"<B's forward kid>","blob":"<b64u>"}
  blob = b64u(epk || nonce || XChaCha20-Poly1305(key, nonce, aad, F))
  F    = hdr_len (2 bytes) || hdr (JSON {to, tdid, tok | cap, pow?}, zero-padded to exactly 1024 bytes) || the raw (not base64) sealed bytes
  key  = HKDF-SHA256(X25519(esk, B.forward.pub), salt = epk || B.forward.pub, info = "p2p/v3/fwd|" + B, 32)
  aad  = "p2p/v3/fwd|" + B + "|" + kid
```
- The blob's size is fixed per sealed bucket: the 1 KiB header, plus the bucket, plus 72 bytes. So A learns the bucket only.
- The largest frame (a 64 KiB bucket) is about 87 KiB in base64, within the 96 KiB frame cap.

**A to B**, on a pooled relay-to-relay connection (§6.4):
```
{"t":"fwd-in","id":"<A's id>","kid":"<kid>","blob":"<b64u>"}
```
- B decrypts the blob and handles the header and sealed bytes exactly as a `send-sealed` (§5.1.2), with the **entry peer** as the source for the per-network limits (§5.1.6).
- B answers `sent` or `error` with the usual codes. A relays the answer back to the client under the client's `id`.

### 6.4 Who may use an entry relay, and how relays talk to each other

- **A forwards only for its own users:** an authenticated device (not restricted) of a userId whose current identity document lists A.
  - A sees which of its users forwards, how much and when. It learns no more than it would from those users' direct sends, minus the recipient.
  - Per-user forward budgets (`limits.fwdPerIssPerMinute`, default 120) and per-IP budgets apply.
  - This keeps relays from becoming open anonymous entry points for strangers and their agents.
- **A dials B's canonical URL** (`wss://…/v3`), checks `hello.relay` against it (H5), and identifies itself as a relay:
  ```
  {"t":"peer","relay":"<A canonical>","forward":{"kid","pub"},"sig":"<b64u Ed25519 over "p2p/v3/peer|" + B + "|" + nonce by A's relay signing key>"}
  ```
  - B may apply per-peer budgets (`limits.fwdInPerPeerPerMinute`) and an operator allowlist or denylist of peers (`FORWARD_PEERS`).
  - Unidentified peers get the per-IP class.
  - The relay signing key is published next to the forwarding key in the well-known document.
- **Connections are pooled:** at most one per peer, reused, and idle-closed after 5 minutes.

### 6.5 Choosing the entry relay

- **The candidates:** the entry is one of the **sender's own** listed relays, never one of the recipient's.
- **Stickiness:** the client picks one, preferring the one that has been its entry longest, and keeps it for 30 days. This is Tor's guard reasoning: a stable entry limits how many operators ever see the client's IP next to its forwarding.
- **Refused routes:** the client refuses a route where A and B are the same relay, share a registrable domain (by the Public Suffix List), or declare the same `operator.contact` in their well-known documents. It sends directly instead (or waits, in strict mode) and tells its user once per pair: `"two-hop skipped: your entry and <recipient>'s relay look like one operator"`.

### 6.6 Why two hops and not three

- **Tor uses three hops** so that no single relay knows both ends while the client can still reach any destination: the guard knows the client, the exit knows the destination, and the middle separates them.
- **Here the last hop is fixed:** it is the recipient's own mailbox relay, which knows the recipient by design. One hop before it already gives "nobody but the sender knows both the sender's IP and the recipient".
- **A middle relay would add** latency and an operator to trust. It defends only against an entry and mailbox relay that collude while the middle doesn't, which is weak given §4.4.
- **Users who want more** combine two-hop with Tor transport to the entry relay.

### 6.7 Why forwarding is not an exit

Forwarding is relay-to-relay only, and the destination must prove it is a relay. The normative rules are in §8.1.

## 7. Design: optional Tor transport

### 7.1 Configuration (strictly opt-in)

In `<P2P_HOME>/config.json`:
```json
{ "transport": "tor" }
```
or, in full:
```json
{ "transport": { "mode": "tor", "socks": "127.0.0.1:9050", "preferOnion": true, "overrides": { "wss://relay.test/v3": "ws://127.0.0.1:8080/v3" } } }
```

- **`mode`:** `"direct"` (the default, and what an absent key means) or `"tor"`. Tor is never the default, and no build, install script or mod ever turns it on by itself.
- **The existing `transport` object** (a map from canonical URL to dial URL, `packages/p2p/src/config.ts`) keeps working. An object whose keys are all relay URLs is read as `overrides`.
- **`P2P_TRANSPORT=tor` in the environment can turn Tor on, but no environment variable turns it off.** Only `config.json` can.
  - The Codex bridge passes `P2P_*` to the `p2p` processes it runs, and a project's own config can set environment variables.
  - Letting the environment *disable* Tor would let a checked-out repository silently move a user's relay traffic off Tor.
  - For the same reason, the bridge's child environment (`childEnv` in `packages/codex-bridge/src/knobs.ts`) already drops every proxy variable, and keeps doing so.
- **`p2p` never reads `HTTPS_PROXY`, `ALL_PROXY` or any other proxy variable for relay traffic.** The agent's own egress (§8) and the client's relay transport stay separate settings, so changing one never silently moves the other.

### 7.2 What goes through Tor

In `tor` mode, **every** network operation the client makes goes through the SOCKS5 proxy, with hostnames resolved by Tor (`socks5h`, never a local DNS lookup). That covers:
- relay WebSockets, both the mailbox and the sealed sending connections;
- the identity document API (`GET …/identity/…`, `tips`, `chain`);
- `/.well-known` fetches, forwarding key fetches, link and invite mailbox operations, and `p2p doctor` probes;
- proof checks: GitHub gists over HTTPS through Tor. **DNS proofs can't be checked through Tor's SOCKS interface**, which resolves A and AAAA records only, not TXT, so they show as `? dns: <claim> (not checked over Tor)`, not as failures;
- avatar fetches (already opt-in, P1).

**Fail closed:** if the SOCKS proxy is unreachable, operations fail with `network: Tor proxy at <addr> unreachable`. There is **no fallback** to direct connections, ever.

**Implementation note:** `ws` takes a custom `agent`, and `fetch` (undici) takes a dispatcher with a custom `connect`. Both are built on one SOCKS5 connector in `packages/p2p`.

### 7.3 Stream isolation

Tor isolates streams that use different SOCKS usernames onto different circuits (`IsolateSOCKSAuth`, on by default). The client sets the SOCKS username to:
- `p2p:mbox:<relay>` for a mailbox connection;
- `p2p:send:<relay>:<random per reopen>` for a sealed sending connection, so each reopen gets a fresh circuit, and never the mailbox connection's;
- `p2p:doc:<random per run>` for document fetches.

Under Tor, a relay therefore can't tie a user's sealed sends to their mailbox connection by exit IP.

### 7.4 `.onion` addresses for relays

**Onion alternates for a clearnet relay** (the common case):
- The relay publishes `"onion":"ws://<56 chars>.onion/v3"` in its `/.well-known/p2p-relay.json` and its `hello`.
- In `tor` mode with `preferOnion` (the default), the client dials that onion address for the canonical URL. That keeps the traffic off Tor exits, and works where the operator's CDN blocks exits.
- **The relay's identity doesn't change:**
  - The canonical URL stays `wss://relay.example.org/v3` in identity documents, caps and `hello.relay`.
  - The hello check (H5) and the auth signature (`"p2p/v3/relay-auth|" + hello.relay + "|" + nonce`) are unchanged.
  - This is exactly the existing transport-override mechanism, a hosts file for relays, filled in from the relay's own published data.
- **The onion address is learned only from the relay itself,** over a TLS-authenticated fetch of its well-known document (through Tor), and re-checked every 24 h.
  - It is **never** taken from a peer's identity document or a relay list. A hostile peer could otherwise point its friends' Tor traffic for a real relay at an onion it runs.
  - `hello` is not signed, so it can't carry that authority by itself either.
- **Onion inside, plain WebSocket:** the onion service already authenticates the server (the address is its key) and encrypts end to end, so the client uses `ws://` inside it, with no TLS certificate needed. This matches how Tor Browser treats `.onion` HTTP.

**Onion-only relays** (no clearnet address):
- **The URL:** the canonical URL is `wss://<56 chars>.onion/v3`. That is already a valid canonical URL (`canonicalRelayUrl` accepts it). It is self-authenticating, so it can appear in identity documents and caps with no new field.
- **Amendment to §5.1 (accepted, Q-C5; lands in T2):** for a `.onion` host, the `wss` scheme in the canonical URL names the relay, and the transport is the onion service, dialled as `ws://` through Tor. TLS is not required, because the onion address authenticates the server.
- **Clients not in Tor mode** treat an onion-only relay as unreachable. They skip it when sending, which costs one of up to three copies (§5.8), and never try to resolve it in DNS.
- **Who uses it:** `p2p relays add wss://….onion/v3` warns that peers without Tor can't deliver through it. Listing only onion relays makes the user unreachable to most peers, so the CLI refuses that unless the user passes `--onion-only`.
- **Old clients and relays** need no change. An old client fails to resolve the name and counts it as a failed copy. Old relays never see the URL except inside caps they don't host.
- This is question Q-T1 in §12.

**Identity documents don't change:** `DOC_FIELDS` is strict in both clients and relays (`packages/core/src/v3/identitydoc.ts`), so adding a field would break everything deployed. Onion alternates live in the relay's well-known document, and onion-only relays are plain canonical URLs.

### 7.5 Relay limits for Tor clients

- **Through exits:** clients that come from Tor exits share exit IPv4 addresses, and the existing shared-IPv4 defaults apply (run-a-relay.md, "IPv4 and IPv6 defaults"). Busy exits can hit per-IP limits. That is one reason to prefer onion.
- **Through the onion service,** every connection arrives from the local `tor` daemon, from a single IP, so per-IP limits would lump all onion users into one bucket. So:
  - **A separate listener:** the relay takes onion traffic on its own listener (`ONION_LISTEN`, bound only to the private network shared with `tor`, never public), and treats it as its own class with its own budgets.
  - **Per-circuit buckets:** with `HiddenServiceExportCircuitID haproxy`, `tor` prefixes each connection with a PROXY-protocol header carrying a per-circuit id. The relay uses that id as the "IP" for per-IP limits on the onion listener.
    - Circuits are cheap, so the onion class also has a class-wide cap (`LIMIT_ONION_CONNECTIONS`), and MAY get a higher PoW (`POW_BITS_ONION`).
    - Per-userId limits apply as usual after auth.
  - **Tor's own defences:** operators SHOULD enable Tor's onion-service DoS defences (`HiddenServicePoWDefensesEnabled 1`, available since Tor 0.4.8).
  - **Never trust the header from anyone else:** the PROXY header is accepted **only** on the onion listener, which must not be reachable from anywhere but the `tor` container or host.

### 7.6 `p2p doctor` in Tor mode

New checks, all read-only. Values are never printed, only presence and kind:

| Check | ✓ | ✗ (with the fix) | ? |
|---|---|---|---|
| `transport` | `tor`, from config.json (or the environment) | an unknown mode → fix config.json | |
| SOCKS proxy | reachable, speaks SOCKS5 | unreachable → "start Tor (`tor` or Tor Browser on 9150), or set `transport.socks`" | |
| It is Tor | an onion dial succeeded (only Tor resolves `.onion`) | | no onion relay configured to test against |
| No direct dials | the transport resolver routed every probe through SOCKS (self-check) | a direct dial was attempted → a bug; report it | |
| Each relay | reachable over Tor via onion or exit, with latency | refused at the exit (CDN challenge, 403) → "this relay blocks Tor exits; it has an onion address: enable `preferOnion`", or "ask the operator" | |
| Each peer's relays | at least one reachable over Tor | none reachable over Tor → "your peer has only relays that block Tor; you can't reach them in Tor mode" | |
| Proofs | | | DNS proofs unchecked (§7.2) |
| Proxy variables | | | "`HTTPS_PROXY` is set in this environment; `p2p` ignores it for relays (see §8 for your agent)", presence only |

In `direct` mode, `p2p doctor` adds one line saying Tor is off, and how to turn it on.

### 7.7 Latency expectations

| | Direct | Tor via exit | Tor via onion |
|---|---|---|---|
| Building the connection | 1 TLS handshake, about 50–300 ms | circuit build and TLS, about 1–3 s | rendezvous, about 2–10 s the first time, faster with a cached descriptor |
| Round trip after connecting | 20–150 ms | 300–1,000 ms | 400–1,500 ms |
| Effect on statuses (every 60 s, live for 150 s) | none | none | none |
| Effect on short commands (`p2p ls`, `send`) | — | about +1–3 s | about +2–10 s on a cold start |

- **Tor-mode defaults:** `P2P_CONNECT_TIMEOUT_MS` defaults to 60 s instead of 10 s, `P2P_REQUEST_TIMEOUT_MS` to 45 s instead of 15 s, and the drain window grows accordingly.
- **The Codex bridge's 30 s child timeout** is raised to 90 s in Tor mode.
- **The mod's status hook** already runs in the background, and is unaffected.

### 7.8 Running a relay as an onion service

To go in [run-a-relay.md](../run-a-relay.md) when phase T2 ships (§13). Sketch:

**Host install:**
```
# /etc/tor/torrc
HiddenServiceDir /var/lib/tor/p2p-relay/
HiddenServicePort 80 127.0.0.1:8081          # the relay's ONION_LISTEN, never exposed publicly
HiddenServiceExportCircuitID haproxy
HiddenServicePoWDefensesEnabled 1
SocksPort 0                                  # this tor only serves the onion; it is not a client
ExitRelay 0
```
Then set `ONION_LISTEN=127.0.0.1:8081` and `ONION_URL=ws://$(cat /var/lib/tor/p2p-relay/hostname)/v3` for the relay. Restart both.

**Docker** (a `tor` sidecar on a private network). Operators build the `tor` image from their distribution's `tor` package rather than pulling an unvetted image:
```yaml
services:
  relay:
    image: peer2peer/relay
    environment:
      RELAY_URL: wss://relay.example.org/v3      # or wss://<56>.onion/v3 for an onion-only relay
      ONION_LISTEN: 0.0.0.0:8081                 # reachable only on the private network below
      ONION_URL: ws://<56 chars>.onion/v3
    ports: ["127.0.0.1:8080:8080"]               # clearnet listener behind your TLS proxy, as today
    volumes: ["p2p-relay:/data"]
    networks: [public, onion]
  tor:
    build: ./tor                                 # FROM debian:stable-slim; apt-get install tor; USER debian-tor
    volumes: ["tor-keys:/var/lib/tor", "./torrc:/etc/tor/torrc:ro"]   # HiddenServicePort 80 relay:8081
    networks: [onion]
networks:
  public: {}
  onion: { internal: true }
volumes: { p2p-relay: {}, tor-keys: {} }
```

**Operator notes:**
- **Back up the onion key.** Keep `hs_ed25519_secret_key` from the `tor-keys` volume. Losing it changes the onion address. Leaking it lets someone else impersonate the onion, although for a clearnet relay it can't impersonate the canonical URL, which clients learn the onion from.
- **An onion service is not a Tor relay, and not a Tor exit.** Running one routes no one else's traffic and creates no exit liability.
- **Publish the address.** Set `ONION_URL` so the relay publishes it in its well-known document and `hello`.

## 8. Bring-your-own egress for agents' web access

### 8.1 Relays never act as exits (normative)

**Rules:**
- **R-X1.** A relay MUST NOT open a network connection to a destination derived from client input, with one exception: forwarding to another Peer2Peer relay under §6, where the destination is a canonical `wss://` relay URL and the relay checks the destination's `hello.relay` before forwarding anything.
- **R-X2.** A relay MUST NOT fetch, resolve or proxy URLs, hostnames or addresses for clients. That includes avatars, proofs, link previews, DNS and "connectivity checks". Clients fetch avatars and check proofs themselves, through their own transport.
- **R-X3.** Forwarding destinations MUST resolve only to public unicast addresses: no loopback, private (RFC 1918, ULA), link-local, CGNAT or multicast ranges, and no cloud metadata addresses. The address MUST be re-checked after DNS resolution, and pinned for the connection, so DNS rebinding can't redirect it. Only the configured port (443 by default, or the port in the canonical URL) is used.
- **R-X4.** A forwarded payload is one fixed-format frame (`fwd-in`) on a Peer2Peer WebSocket. A relay never forwards raw bytes, never opens a TCP stream on a client's behalf, and never speaks any protocol but its own to the destination.
- **R-X5.** Conforming relay software ships no exit, proxy or fetch feature, and the operator guide says so.

**Why:**
1. **Liability for volunteer operators.**
   - A relay operator's IP would become the visible source of whatever its users and their agents fetch: scraping, credential stuffing, piracy, harassment, attacks.
   - Tor exit operators get abuse complaints, DMCA notices, blocklisting, and police visits.
   - Most VPS and hosting terms forbid open proxies outright.
   - We ask volunteers to run relays because a relay is a dumb store of ciphertext that does nothing on the open internet. An exit role would end that bargain, and with it the volunteer network.
2. **Abuse by automated agents.**
   - Agents run unattended, at machine speed and at scale.
   - A relay network that offered egress would become free, rotating anonymity infrastructure for scraping, evading blocks, and automated attacks, run by our users' agents or by anyone's.
   - Every agent would be one prompt injection away from using it.
   - Unlike people, agents don't tire of retrying, so per-IP limits at an exit get exhausted at once.
3. **SSRF against operators.** Any fetch-on-behalf feature on a relay is a path from the internet into the operator's private network and cloud metadata service. R-X3 exists even for relay-to-relay forwarding for this reason.
4. **It isn't needed.** Nothing in the protocol needs relays to reach the web. Users who want private egress already have accountable options (Tor, a VPN, a corporate proxy), which they control and answer for (§8.2).

### 8.2 What the client does: configuration, not a feature

**Agent web traffic never touches Peer2Peer.** The `p2p` CLI, the Claude Code mod and the Codex bridge never fetch the web for an agent, and relays never see agent web traffic. "Bring your own egress" means configuring the agent runtime's own proxy settings. Our part is documentation, plus one read-only `p2p doctor` report.

**Claude Code (the mod's context):**
- **Proxy settings:** Claude Code honours `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (lowercase too), from the environment or from the `env` block of `~/.claude/settings.json`. It **does not support SOCKS proxies** (Claude Code docs, "Enterprise network configuration"). Settings in `~/.claude/settings.json` are the only ones that reach background agents reliably.
- **Using Tor:** run Tor with an HTTP CONNECT port (`HTTPTunnelPort 9080` in torrc), then set `HTTPS_PROXY=http://127.0.0.1:9080`. For a VPN, nothing is needed. For a corporate proxy, use its HTTP URL.
- **Watch out:** these variables also carry the model API traffic (`api.anthropic.com`) and the WebFetch domain-safety check, which reports the domain being fetched to the provider. Users who want only tool fetches through Tor exempt the provider with `NO_PROXY=api.anthropic.com,claude.ai,platform.claude.com`. Whether the provider accepts Tor exits is up to the provider.
- **Provider-hosted tools,** such as hosted web search, run on the provider's side. No local proxy affects them.
- **Shell commands** the agent runs (`curl`, `git`) inherit the environment. Most honour `HTTPS_PROXY`, and some honour `ALL_PROXY=socks5h://…`.
- **The mod sets none of this.** It spawns `p2p`, which ignores proxy variables for relays (§7.1), so a user's agent egress choice never changes how relay traffic flows, and the other way round.

**Codex (the bridge's context):**
- **Sandbox network:** commands in the `workspace-write` sandbox have no network unless `sandbox_workspace_write.network_access = true`. Codex also has an experimental proxy for sandboxed commands (`features.network_proxy`, with `proxy_url` and `socks_url` and a domain allowlist). Per its docs, that proxy does not filter web search, apps, MCP or other hosted tools.
- **Hosted web search:** `web_search` (`disabled`, `cached`, `indexed` or `live`) is hosted. A local proxy doesn't route it.
- **Environment:** shell commands get the environment that `shell_environment_policy` allows, so proxy variables reach them only if that policy passes them.
- **The bridge sets none of this,** and its `p2p` children never get proxy variables (`childEnv`).

**`p2p doctor --egress`** (read-only, in phase E1):
- For each runtime it finds (Claude Code settings, the Codex config), it reports whether a proxy is configured and its scheme (`http`, `https`, `socks5h`). It never reports the value: no host, no credentials.
- It reports whether `NO_PROXY` exempts the model provider.
- It reports whether Codex's sandbox network is on.
- It ends with a reminder that relays never carry agent web traffic.
- It reads config files only as needed for those fields (the "Assessor secret configs" rule: field projections only).

**Recommendation:** documentation plus the doctor report. Building our own proxied fetch tool (an MCP fetch server routed through the user's proxy) would make Peer2Peer responsible for agent web egress. It would duplicate what each runtime already configures, and blur the boundary in §8.1 (alternatives, §11).

## 9. Compatibility and rollout

### 9.1 Gates

- **Client support** is advertised in status `caps` (§4.3, "Status caps"):
  - `sealed.v1`: understands the sealed wrapper with padding, `tokens`, sealed delivery frames and `recv-sealed`.
  - `cover.v1` (informational only): the session sends cover traffic, so peers don't flag loop dummies or slot timing as faults.
- **Per device:** a sender uses sealed sending to device `d` only when **all** of these hold:
  1. the latest status it holds from a session on `d` (by `fdid`), at most 7 days old, advertised `sealed.v1`;
  2. the mailbox relay advertises `sealed.v1` in `hello.features`;
  3. it holds an unspent token for that relay and recipient, or an applicable `sub:"*"` cap.

  Otherwise it sends unsealed, exactly as today, except in strict mode (§9.3). The gate is per device, not per user: a device that hasn't upgraded gets unsealed envelopes, while that user's other devices get sealed ones.
- **Relay support** is advertised in `hello` and in the well-known document as `"features":["sealed.v1","fwd.v1"]`, plus the optional `"forward"` and `"onion"` objects.
  - Clients ignore unknown `hello` fields today (`relay-client.ts` reads only `relay`, `nonce`, `pow` and `limits`), so adding these is safe.
  - A pre-RFC relay answers `send-sealed`, `tok-reg` or `fwd` with an error (an unknown frame type). Clients treat that as "no support", and cache it until the next `hello`.
- **Status caps cost:** at most 16 caps per status, and this adds one (`sealed.v1`), or two with `cover.v1`.
- **Nothing in the outer envelope or the inner plaintexts changes,** so no `v` bump. Like the status-caps amendment, this is a draft 3 amendment, approved because nothing is public yet.

### 9.2 Rollout steps (the status-caps pattern)

| Step | Release | Sends sealed by default? | Who is affected |
|---|---|---|---|
| **S0** | relays ship `sealed.v1` (and later `fwd.v1`) | no clients send yet | none; relays only accept new frames |
| **S1** | clients ship the receive path, token issuance, the `sealed.v1` cap, and sending **opt-in** (`"privacy": "sealed"` in config.json, or `P2P_PRIVACY=sealed`) | no | users who opt in. Receivers on S1 or later can take sealed envelopes, so they register tokens, send `recv-sealed`, and advertise `sealed.v1`. |
| **S2** | once S1 is the deployed floor: sealed with padding on by default for peers whose devices advertise `sealed.v1` | yes, where gated (§9.1) | everyone; old peers still get unsealed. Opt out with `"privacy": "standard"`. |
| **S3** | optional and independent: `cover`, two-hop (`"hop": "auto"`), `transport: tor` | never by default | users who opt in |

- **Cost of skipping the steps:** a client that sent sealed envelopes before its peers could open them would lose sight of those peers. The same failure the status-caps amendment avoided for `caps` was avoided the same way.
- **Status caps go first:** status caps are on by default since P1, so peers can see `sealed.v1` from S1 on.

### 9.3 The `privacy` setting

| Value | Behaviour |
|---|---|
| `standard` | today's behaviour (the default before S2) |
| `sealed` | seal wherever gated, otherwise send unsealed (the default from S2) |
| `strict` | seal wherever gated. Otherwise **don't send**: the envelope waits up to 24 h for a token or an upgraded peer, and `p2p send` and `status` report `held: unsealed-only peer`. First contact with a cap-less stranger asks before sending unsealed. |

`hop` (`off` or `auto`) and `cover` (`off`, `jitter` or `constant`) are separate settings. All three live in config.json. Environment variables may only strengthen them (raise `privacy`, turn on `hop` or `cover`), never weaken them, for the same reason as §7.1.

## 10. Costs

**Assumptions:** one active session, 50 peers, 2 relays, statuses every 60 s, about 2 KiB status plaintext.

| Mechanism | Latency | Client bandwidth | Relay cost |
|---|---|---|---|
| **Sealed wrapper** | about 0.1 ms CPU per send (one X25519 and one AEAD) | +72 bytes plus base64 per envelope | no envelope signature check on sealed sends (cheaper); one SHA-256 per token check |
| **Sending connection** | +1 TLS handshake (about 50–300 ms) per reopen, every ≤ 10 minutes or after 60 s idle. Sends in a burst share one connection. | +1 TLS handshake per reopen (about 5 KB) | more short-lived connections: at most ≈ 6 an hour per active user per relay |
| **Tokens** | none on the send path | issuing: 32 tokens × 50 peers × 2 relays ≈ 3,200 tokens/day ≈ 51 KB/day (as about 100 `tokens` envelopes); receiving about the same from peers | storage about 48 B per token: 1,600 tokens/day per user per relay ≈ 77 KB, kept at most 7 days (≈ 0.5 MB per active user per relay at most); one `tok-reg` a day |
| **Padding** | none | statuses about 2.1 KiB → a 4 KiB bucket (1.9×). Across a realistic mix, roughly 1.3–1.5× on sealed bytes; worst case 2×. | the same factor on stored and forwarded bytes. Mailbox caps count padded bytes, so a mailbox fills about 1.4× sooner. |
| **`jitter`** | 0–20 s on statuses and other non-interactive sends | none | none |
| **`constant`, 15 s slots** | up to 15 s per send, more when queued | 4 KiB × 5,760 slots/day ≈ 23 MB/day per relay connection (≈ 46 MB/day for 2 relays). A 60 s slot is about 11.5 MB/day for 2 relays. | the dummies are stored until the user's own device acks them (seconds when online) |
| **Two-hop** | +1 relay-to-relay hop, about 20–150 ms over a pooled connection; +1 forwarding key fetch per 30 days | +1 KiB header per send | the entry relay carries each forwarded byte twice (in and out); the mailbox relay decrypts one more layer |
| **Tor** | §7.7: +1–10 s connecting, 300–1,500 ms round trips | Tor cell overhead, about +5–10% | none for exits; one `tor` daemon for an onion service |

## 11. Alternatives considered

| Alternative | Why not (now) |
|---|---|
| **One shared delivery key per recipient** (Signal's unidentified access key) for friends | Maximum anonymity among senders, but no per-sender budget or targeted revocation: one leaked key means re-keying every friend. We use this shape only where it already exists, in circle join caps (§5.1.5). |
| **Anonymous credentials** (blind RSA, RFC 9474; VOPRF and Privacy Pass, RFC 9497 and RFC 9576–9578; zkgroup) | Single-use unlinkability with fewer tokens to hand out. Needs new cryptography in core and relays, and verification costs at the relay. Deferred: the `tok` field can later carry a credential (Q-T5). |
| **Single-use tokens (`uses = 1`) by default** | Unlinkable by token, but about 64× the issuance and storage. `uses` is a per-grant parameter, so a user or a later default can choose it. |
| **Padmé padding, or a single fixed size** | Padmé leaks more bits per size. A single 64 KiB size multiplies bandwidth about 30× for statuses. |
| **A mixnet (Loopix and Nym style)** | The only real defence against a GPA, but needs per-hop delays measured in seconds, continuous two-way cover traffic and a mix directory. Wrong cost and latency for 60-second presence on laptops; better as a transport someone can plug in later. |
| **Three-hop onion routing between relays** | No gain when the last hop is the recipient's own mailbox relay (§6.6). |
| **Requiring Tor, or making it the default** | Excluded by the approved scope. Tor is also slow, blocked on some networks, legally fraught in some jurisdictions, and a support burden. Users who want it opt in. |
| **Relays as exits, or a relay-hosted fetch service** | Excluded, never (§8.1). |
| **Private information retrieval or broadcast for mailboxes** (hiding the recipient) | Bandwidth or server CPU grows with the number of users. Out of scope (§3.2). |
| **A field in identity documents for onion addresses** | `DOC_FIELDS` is strict in every deployed client and relay. A peer can't vouch for a relay's onion address in any case (§7.4). |
| **Honouring `HTTPS_PROXY` and `ALL_PROXY` for relay traffic** | Couples the agent's egress to relay traffic invisibly, and lets a repository's environment move relay traffic (§7.1). A deliberate `transport` setting is safer. |
| **A Peer2Peer-provided proxied fetch tool for agents** | Makes us responsible for agent web egress, duplicates runtime settings, and blurs §8.1 (§8.2). |
| **Hiding the sender's device but not its user** (sealing only `fdid`) | Little privacy gain for the same machinery. |

## 12. Open questions

### 12.1 For the CEO (decided 2026-10-23)

The CEO accepted every recommendation below on 2026-10-23. Each question keeps its original wording, followed by the decision.

- **Q-C1. Should sealed with padding become the default at S2,** or stay opt-in? *Recommendation: default-on at S2.* Its cost is modest (§10). Cover traffic, two-hop and Tor stay opt-in.
  - **Decided (2026-10-23): default-on at S2.** Sealed sender with padding becomes the default once S1 is the deployed floor. Cover traffic, two-hop and Tor stay opt-in.
- **Q-C2. Who may use a relay as a two-hop entry?** *Recommendation: only the relay's own users,* those whose identity document lists it (§6.4). The alternative, open entry for anyone, gives stronger anonymity sets, but makes every relay an anonymous entry point for strangers' agents, which the operator answers for.
  - **Decided (2026-10-23): only the relay's own users** (an authenticated device of a userId whose current identity document lists the relay) may use it as an entry.
- **Q-C3. May strangers make first contact sealed with PoW alone,** without an invite cap? *Recommendation: no.* Cold contact stays unsealed and PoW-gated (§5.1.5). Sealed first contact needs an invite's `sub:"*"` contact cap.
  - **Decided (2026-10-23): no.** Cold contact stays unsealed and PoW-gated. Sealed first contact needs an invite's `sub:"*"` contact cap.
- **Q-C4. Should Ix's public relay offer an onion address** (and later an onion-only sister relay), and should Ix fund or court independent relay operators? Two-hop only helps across operators (§4.4, §6.5). *Recommendation: yes to the onion address in phase T2,* and seek at least one independent community relay before promoting two-hop.
  - **Decided (2026-10-23): yes.** The public relay gets an onion address in phase T2, and Ix seeks at least one independent community relay before two-hop is promoted.
- **Q-C5. May onion-only relays appear in identity documents?** This needs the §5.1 amendment, "the `wss` scheme is nominal for `.onion`" (§7.4). *Recommendation: allow, with CLI warnings,* and refuse onion-only relay lists without `--onion-only`.
  - **Decided (2026-10-23): allow,** with the §5.1 amendment (`wss` is nominal for `.onion`) landing in T2. The CLI warns when an onion-only relay is added, and refuses an onion-only relay list without `--onion-only`.
- **Q-C6. BYO egress scope:** documentation plus `p2p doctor --egress`, or should we build a proxied fetch tool? *Recommendation: docs and doctor only* (§8.2).
  - **Decided (2026-10-23): documentation and `p2p doctor --egress` only** (phase E1). No proxied fetch tool.
- **Q-C7. Default token linkability:** `uses = 64` (sends linkable for about an hour per session, about 0.5 MB per user per relay at most), or more private and costlier (`uses = 8`, about 4 MB)? *Recommendation: 64,* adjustable per user.
  - **Decided (2026-10-23): `uses = 64` by default,** adjustable per user.
- **Q-C8. Positioning:** should "Tor support" be marketed, or documented quietly? It matters for app-store and enterprise perception, and for jurisdictions where Tor use draws attention. *Recommendation: document it in the operator and user guides; don't headline it.*
  - **Decided (2026-10-23): document Tor support** in the operator and user guides, and don't headline it.

### 12.2 Technical

- **Q-T1.** The onion-only canonical URL rule (§7.4): keep `wss` as a nominal scheme, or define `ws://….onion` as canonical? The second breaks the "wss only" invariant every deployed parser enforces, which is why this RFC proposes the first.
- **Q-T2.** Ephemeral per-conversation sender identities, the fix for statistical disclosure suggested by Martiny et al.: worth the complexity for agent traffic?
- **Q-T3.** Recipient-side cover traffic (relay-generated dummy deliveries) without the relay being able to tell real deliveries from dummies.
- **Q-T4.** Receiving through a hop: fetching one's own mailbox through the entry relay, to hide the recipient's IP from the mailbox relay without Tor. It needs device authentication carried through A, end to end to B.
- **Q-T5.** A credential-based `tok` format (blind RSA or VOPRF) to replace multi-use tokens.
- **Q-T6.** Whether relays should also pad `env` delivery batching (deliver in fixed-size batches on a timer) to blunt arrival timing.
- **Q-T7.** Whether `p2p` should check its SOCKS endpoint really is Tor without contacting a third party. This RFC infers it from a successful onion dial.

## 13. Implementation plan (one PR per phase)

Ordered after the remaining footprint phases. Each PR carries its own spec text in protocol.md (as the status-caps amendment did), tests, and a review-log entry. CI is dispatch-only. E1 and T1 don't depend on sealed sender, and can go earlier if the CEO wants.

| Phase | PR | Contents | Depends on |
|---|---|---|---|
| **R0** | this RFC (accepted 2026-10-23) | `docs/rfcs/0001-metadata-privacy-and-tor.md` and a pointer in protocol.md | — |
| **E1** | BYO egress docs | the mod README and bridge README "Agent web egress" sections (§8.2); a run-a-relay.md "never an exit" paragraph (§8.1); `p2p doctor --egress` (presence and scheme only) | — |
| **S-core** | core: the sealed wrapper and tokens | `@peer2peer/core/v3`: seal and open with the padding codec (§5.1.1, §5.2), token hashing, the `tokens` kind validator, the `sealed.v1` cap constant (not yet emitted), and test vectors (including Go vectors if the Go port takes them) | — |
| **S-relay** | relay: the sealed path (S0) | `features` in `hello` and the well-known document; `tok-reg`, `tok-revoke` and token storage with the sweep; `send-sealed` (token and `*`-cap paths, PoW over sealed bytes, uniform answers); `recv-sealed` and sealed delivery; per-ticket `srcTag`; new limits in `hello.limits`; aggregate metrics only (no counter that tells delivered from dropped); the resilience suite | S-core |
| **S-client** | p2p: sealed opt-in (S1) | issuing, handing out and refilling tokens; revoking on unfriend, block and removal; receiving sealed; sending sealed per device under `"privacy": "sealed"`; sending-connection management; strict mode; `p2p doctor` sealed checks; the mod and bridge pick it up through `p2p` (bundle regenerated) | S-relay deployed on the public relay |
| **S-default** | sealed on by default (S2) | flip the default to `sealed`; protocol.md review-log entry | S-client as the deployed floor |
| **T1** | p2p: Tor transport | the SOCKS5h connector for `ws` and `fetch`; `transport` modes; fail-closed; environment can only turn it on; stream isolation; DNS proofs as `?`; Tor-mode timeouts; doctor checks (§7.6); the bridge's child timeout | — |
| **T2** | relay: onion service | `ONION_LISTEN` with PROXY-protocol circuit ids, the onion class limits, `onion` in the well-known document and `hello`, a run-a-relay.md Tor section and Docker compose example (§7.8); client `preferOnion`; the §5.1 onion-only amendment (if Q-C5 is yes) | T1 |
| **H1** | two-hop forwarding | relay forwarding and signing keys; `fwd`, `fwd-in` and `peer`; SSRF guard (R-X3); per-user, per-peer and allowlist budgets; client entry choice and operator-diversity rule (§6.5); `"hop": "auto"` | S-client |
| **C1** | cover traffic | `jitter` and `constant` modes; loop dummies with self-issued tokens; loop-loss reporting in doctor; `cover.v1` | S-client |

## 14. References

- protocol.md §4 (envelopes), §5 (relays), §7 (security notes); [run-a-relay.md](../run-a-relay.md); the status-caps amendment (the cap-gated rollout pattern).
- Signal, "Technology preview: Sealed sender for Signal" (2018); Signal, group send endorsements (2024).
- I. Martiny, G. Kaptchuk, A. Aviv, D. Roche, E. Wustrow, "Improving Signal's Sealed Sender", NDSS 2021.
- A. M. Piotrowska, J. Hayes, T. Elahi, S. Meiser, G. Danezis, "The Loopix Anonymity System", USENIX Security 2017.
- R. Dingledine, N. Mathewson, P. Syverson, "Tor: The Second-Generation Onion Router", USENIX Security 2004; Tor onion service PoW defences (Tor 0.4.8); `HiddenServiceExportCircuitID`, `IsolateSOCKSAuth`, `HTTPTunnelPort` (tor manual).
- RFC 9458 (Oblivious HTTP), RFC 9180 (HPKE), RFC 9474 (blind RSA), RFC 9497 (OPRFs), RFC 9576–9578 (Privacy Pass).
- G. Danezis, "Statistical Disclosure Attacks", 2003.
- K. Nikitin et al., "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (Padmé), PETS 2019.
- Claude Code docs, "Enterprise network configuration" (proxy variables, no SOCKS); Codex config reference (`sandbox_workspace_write.network_access`, `web_search`, `features.network_proxy`, `shell_environment_policy`).
