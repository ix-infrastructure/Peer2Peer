# RFC 0002: Circle version floors (version alignment)

| | |
|---|---|
| **Status** | Proposed, revised after security review (see section 9). Open for comment on [#37](https://github.com/ix-infrastructure/Peer2Peer/issues/37); at least 14 days per GOVERNANCE.md. Nothing here is implemented. |
| **Date** | 2026-11-05, revised 2026-11-19 |
| **Applies to** | [protocol.md](../protocol.md) v3 draft 3 (protocol 3.1), §3.3 circle versions and proposals, as an additive amendment with a two-step rollout per [compatibility.md](../compatibility.md) |
| **Discussion** | [#37](https://github.com/ix-infrastructure/Peer2Peer/issues/37) |

Words in capitals (MUST, SHOULD, MAY) are used as in RFC 2119. Section signs (§) without a file name point into [protocol.md](../protocol.md).

## 1. Summary

A circle can carry an optional, signed **floor**: the oldest protocol minor and the feature caps its members' clients should have. The field is `requires: {proto, features, from}` in the circle version (§3.3). It is set by the owner, or proposed by an admin and approved by the owner.

- **A floor only.** It names a minimum and never a maximum, so nothing can use it to make a client downgrade.
- **It never removes anyone and changes no authorisation.** A member below the floor stays a member. It is told, in every front end, that the circle needs a newer Peer2Peer. It keeps being sent everything its client can handle.
- **Announced before it's enforced.** A floor takes effect no earlier than `from`, at least 14 days after the version that sets it, and no earlier than 14 days after each receiver first saw it. Until then it only produces notices.
- **Informational, not critical.** `requires` MUST NOT be listed in `crit`. A client that doesn't understand it ignores it and keeps today's rules, which is the conservative outcome (section 5.1).

Feature use inside a circle stays decided per message by positive evidence (`peerSupports`, [compatibility.md](../compatibility.md)). The floor adds two things: a visible, signed statement of what the circle expects, with notices to whoever is behind; and, for features registered as circle-wide (section 4.4), permission to use the feature after the floor is in effect even when a member below the floor lacks it. That member gets the feature's registered fallback, never a broken message.

## 2. Motivation

The compatibility policy keeps every release interoperating with the previous two, and features roll out in two steps so older clients never see what they would reject. That works peer to peer. A circle adds problems of its own:

- **Nobody can see the lag.** Per-user features such as status `agents` and extension state are already decided per recipient (`peerSupports({all})`), so a lagging member silently gets the fallback. Nobody, including that member, is told why. An owner has no list of which members are behind.
- **The weakest client decides forever.** A feature that only makes sense circle-wide, such as a future sealed-sender or padding mode from RFC 0001, stays off for everyone as long as one member's client lags. One device that is never updated keeps it off for good.
- **There is no way to say "this circle needs X".** That includes properties a team wants all of its members to have (for example "only clients with project boundaries", `projects.v1`).

Version alignment gives the circle a signed, visible statement of what it expects, a grace period to get there, and a clear notice to whoever is behind. It doesn't change who is a member or what anyone may send.

## 3. Goals and non-goals

### 3.1 Goals

- **G1.** Members learn each other's protocol minor and caps from what is already published (status `caps`, `dinfo`). No new metadata is involved.
- **G2.** A circle-wide feature is used only when every live member supports it (`peerSupports({all, cid})`), or when the circle's floor, in effect, lists it.
- **G3.** A member below the floor is told, in `p2p doctor`, `p2p tui`, the Claude mod and the Codex bridge: "this circle needs Peer2Peer with proto ≥ 3.x and <features>; update". It stays a member and is still sent everything it can handle.
- **G4.** The owner and admins can list members who are below the floor, or would be below a proposed one.
- **G5.** A floor can't cut members off by surprise, force a downgrade, or serve as a denial of service.

### 3.2 Non-goals

- **No maximum, pinning or downgrade.** Clients never run an older protocol because a circle says so.
- **No automatic removal.** Removing a member stays a deliberate `propose remove` by a person.
- **No authorisation.** A floor grants and withholds nothing. "Meets the floor" is never an assurance about a member's client (caps are self-asserted, section 6).
- **No exact versions on the wire.** A floor names protocol minors and feature caps, never a client version string, matching the status rule against exact versions (compatibility.md "Where it's advertised").
- **No relay involvement.** Relays don't read or enforce floors. Section 6 covers what they can still observe.

## 4. Proposed spec text (§3.3 amendment)

### 4.1 The field

A circle version MAY carry:

```
"requires": { "proto": "3.<minor>", "features": ["<cap>", ...]?, "from": <s> }
```

- `proto`: a string `"3.<minor>"`, where `<minor>` is a decimal integer from 1 to 999, no leading zeros. It means "a client whose status caps include `proto.3.<m>` with m ≥ minor".
- `features`: optional. When present, 1 to 8 entries, each matching the status caps charset (§4.3), sorted ascending by UTF-8 byte order, with no duplicates. An empty array, an unsorted array or a duplicate makes the version `malformed`. Receivers accept any charset-valid name; what they show for a cap they don't know is in section 4.3.
- `from`: the earliest time enforcement may begin, as Unix seconds: an integer with 0 ≤ `from` ≤ 2^53 − 1. A far-future `from` is allowed and harmless: the floor is announced but never takes effect.
- `requires` is **informational** and MUST NOT be listed in the version's `crit`. A version that lists it in `crit` is `malformed`.
- Any other shape (an unknown key inside `requires`, a wrong type, a value out of range) makes the version `malformed`.

**Comparing floors.** "Unchanged" means equal after parsing (the same `proto` minor and the same sorted `features`), not byte-equal JSON. A floor N is a **relaxation** of floor P when N is absent, or when N's minor ≤ P's minor and N's features ⊆ P's features. Anything that isn't a relaxation is a **raise**: setting a floor where there was none, a higher `proto`, an added feature, or a change that raises one part and lowers another. The **meet** of two floors keeps only what both ask for: the lower minor and the common features (absent when there are none); the meet with an absent floor is absent.

**Rules on signed content** (every receiver checks them; breaking one makes the version `malformed`):
1. **Against `ver − 1` only.** Raise, relaxation and unchanged are always decided against the floor in version `ver − 1` on the client's accepted chain, never against a discarded sibling.
2. **Raises need notice.** A version that raises the floor carries `from ≥ iat + 14 × 86400`.
3. **Unchanged keeps `from`.** A version with an unchanged floor and a different `from` is treated as a raise, so rule 2 applies to it.
4. **No backdated raises.** A version that raises the floor MUST have `iat` ≥ the `iat` of version `ver − 1`. *Why malformed rather than ignored:* the check is deterministic for every receiver, and ignoring the change instead would leave later versions' raise/unchanged comparisons ambiguous. The reference owner's client never produces such a version (section 4.5), so it comes only from a broken or hostile signer, who could already make any version `malformed`.

A relaxation's `from` is informational: the owner's client sets it as in section 4.5, but receivers don't use it (section 4.3). Relaxations take effect at once and never move enforcement earlier.

**After a fork** (§3.3 siblings), a floor that the discarded branch set and the owner's client re-applies is a new raise, with a fresh `from`.

**Transfers.** A version carrying `transfer` keeps the previous `requires` and `from` unchanged. A client SHOULD understand floors before it accepts ownership of a circle that has one. If it doesn't, its next version drops the field, which is a removal: it only relaxes.

**Proposals.** An admin proposes a floor with `op: "requires"` and a new proposal field:

```
"op": "requires", "requires": { "proto": "3.<minor>", "features": ["<cap>", ...]? } | null
```

- `null` removes the floor. The object has the shape and rules above, without `from`, which the owner's client sets. Any other shape makes the proposal `malformed`. The field appears only with this op, so it isn't critical: an owner's client that doesn't know the op refuses the proposal.
- **Never applied automatically.** `op: "requires"` proposals always wait for the owner's approval, whatever the hold policy.
- **Staleness.** For the stale rule (§3.3, "no version after `base` changed the same `target`"), a `requires` proposal targets the circle's floor: it is stale when any version after `base` changed `requires` (its floor or its `from`).

### 4.2 Discovery

- A member's capabilities are read from the evidence the client already holds, per device:
  1. the device's live statuses (within the 150 s liveness window);
  2. its `dinfo` entry;
  3. its latest statuses.

  When sources disagree, the newer evidence wins: a live status overrides an older `dinfo` entry, so a device that has just upgraded stops being "below" at once. Evidence older than 30 days is ignored for the below/unknown decision, so a device that is never seen again can't keep its user "below" for good.
- A member **meets** the floor when at least one of its devices shows `proto.3.<m>` with m ≥ the floor's minor and every listed feature. A member **is below** the floor when every device the client has evidence for shows something missing.
- With no evidence at all, the member is **unknown**. It is never counted as below, so a silent member gets no notice from others, and its own client decides for itself (section 4.3).
- `peerSupports` gains a circle scope: `{all, cid}` says yes when every live session of every member standing in the circle lists the feature, and there is at least one. Only features registered as circle-wide in section 4.4 use it. Per-user features keep `{all}`.

### 4.3 What clients do

**Local floor state.** Each client keeps, with the circle, the floor **in effect** (E) and at most one **announced** floor (A) with its local enforcement time T. On accepting a version with floor N:
- E becomes the meet of E and N at once. Relaxations, including the relaxed part of a mixed change, apply immediately.
- If N is a raise, A becomes N and T = max(`from`, t_first + 14 × 86400), where t_first is when this client first accepted a version on its accepted chain that set or raised to N (local clock, kept with the circle). The signed `from` is the earliest enforcement time, never a promise that enforcement has started. A late delivery, a slow owner clock or a backdated `iat` therefore still leaves every receiver 14 days of notice.
- If N is a relaxation and A exists, A becomes N and T is kept, so lowering never moves enforcement earlier. If N is a relaxation and there is no A, E is N.
- At T, E becomes A and A is cleared. The previously effective floor stays in effect until then.
- When the client switches to another branch, it recomputes this state from the accepted chain. A joiner that receives a long history at once has t_first = now for the current floor, so it treats the floor as announced for its first 14 days.

**A member's own client:**
- When its own caps don't meet E or A in a circle it stands in, it shows "<circle> needs Peer2Peer with proto ≥ 3.x [and <features>]; update. Set by <owner fingerprint>." The wording changes when the floor is in effect ("…is in effect").
- The notice text is fixed by the client. It never carries a link or any text from a peer, other than the circle name, which passes the usual peer-text sanitiser. It points only to the client's built-in update instructions.
- **Floors no client knows.** When the floor's `proto` minor is greater than the newest minor this client knows of, the notice says "this circle asks for a Peer2Peer version newer than any this client knows of" and appears in `p2p doctor` only, not in session-start notices or toasts.
- **Caps it doesn't know.** A listed feature that isn't in this client's registry and has an `x:` prefix is shown as "unknown requirement set by <owner fingerprint>", not as "update Peer2Peer". One without the prefix is shown as a feature this client doesn't know, with the update notice.
- The notice appears in `p2p doctor`, `p2p circle ls`/`members`, `p2p tui`, the Claude mod (`/peers doctor`, the session-start notice) and the Codex bridge (`p2p codex held` and its MCP `doctor`). Outside doctor it shows at most once a day per circle, and a person can suppress it per circle (doctor still shows it).
- Nothing else changes: it keeps its membership, its join statement and every feature it has.

**Every other member's client:**
- A floor changes sends only for features registered as circle-wide in section 4.4, and only once that feature is in E. Then the feature is used even when a member below the floor lacks it, and that member gets the feature's registered fallback. Nothing is held for it, and a send to it never fails or degrades silently.
- Before that, and for every feature not in E, the `{all, cid}` rule applies, as today.
- Per-user features (status `agents`, extension state, receipts, project boundaries) keep their own rules unchanged. A floor that lists them, or only `proto`, is **notice-only**: it produces notices and the admin view, and changes nothing on the wire.
- A floor never makes a client refuse an envelope, a status or a membership statement from a member below it.

**Admin view:**
- `p2p circle members <cid>` and `p2p doctor` show E, A and T, and list each member who is below or unknown, as "below: proto 3.1, missing agents.v1".
- `p2p circle members <cid> --would-require '<json>'` shows the same for a proposed floor before anyone sets it.
- The admin view uses only evidence the viewing client already holds for other reasons, and never asks a member for anything.
- Notice periods are computed locally: the owner's client counts from when it published the announcing version, on its own clock. Members don't acknowledge notices, and nothing waits for acknowledgements.

**Agent sessions.** Setting, proposing or approving a floor, and `--would-require` (which reveals members' versions), are a person's actions. They are refused from an agent's session like other circle changes, and are added to the guarded commands of the Claude mod and the Codex bridge.

### 4.4 Floorable features

The owner's client lists only registered caps. Each registration states the scope the floor changes and the exact fallback:

| Cap | Kind | Scope the floor changes | Effect once in effect | Fallback for a member below the floor |
|---|---|---|---|---|
| `agents.v1` | notice-only | none (stays `{all}` per user) | none on the wire | unchanged: the `(+N agents)` summary (§4.3) |
| `xstate.v1` | notice-only | none (stays `{all}` per user) | none on the wire | unchanged: no state kinds (§4.3) |
| `projects.v1` | notice-only | none | none on the wire | unchanged: the existing `not_shared` rule for a user's own devices without project boundaries ([compatibility.md](../compatibility.md)) |

- **`projects.v1` and `not_shared`.** Project boundaries already stop a session with a ceiling from sending to the user's own devices that lack `projects.v1`. That rule is about one user's own devices and is stricter than anything a floor does. A floor never adds a `not_shared` and never lifts one; listing `projects.v1` only tells members whose clients lack project boundaries that the circle expects them.
- **`receipts.v1` and `invite.circles.v1`** aren't floorable: receipts are decided per session (`{sid}`) and circle invites per redeemer, so a circle floor has nothing to change for them.
- **Circle-wide caps.** A cap whose send is decided with `{all, cid}` (for example a future RFC 0001 mode) is registered as *circle-wide*, with its fallback. Where the feature allows, the fallback MUST go under the same outer `kind` and a size class shared with the full form, so relays can't tell the two apart (section 6). None is registered yet.
- Adding a cap is a spec PR under §8-style first-come registration, with its row in this table. Receivers never refuse a version for a cap they don't know (section 4.3).

### 4.5 The owner's client when signing

The reference owner's client signs a version that sets, raises, relaxes or repeats a floor only when:
- `iat` = max(now, `iat` of version `ver − 1`);
- for a raise, `from` ≥ `iat` + 14 × 86400 (the default grace; the owner may choose later);
- for a relaxation, `from` = max(`iat`, previous `from`) while the previous floor wasn't yet in effect, and `iat` when it was;
- `proto` ≤ its own minor, and every feature is registered and one it has;
- every device in its own `keyholders` advertises `circle.requires.v1`. Otherwise an older key-holding device, as single writer, could sign the next version without the field and drop the floor by accident, or raise a false "version I didn't publish" alert;
- the step-2 guard in section 5.2 holds.

None of these checks binds a hostile signer: a stolen owner key, a modified client or another implementation can skip them. What protects receivers is that `requires` is ignored by clients that don't understand it, the receiver-side grace and relaxation rules in section 4.3, the `malformed` rules in section 4.1, and the notice limits.

## 5. Compatibility and rollout

### 5.1 Why `requires` isn't critical

compatibility.md requires `crit` for a field that restricts what an object allows: a narrower cap, a narrower audience, an extra condition on a membership. `requires` doesn't do that. It narrows no authorisation: it doesn't change who is a member, who may send, or what a member may receive. A client that ignores it keeps the `{all, cid}` rule for circle-wide features, which holds back a feature the floor would have let it use. Ignoring the field therefore never allows more than the issuer meant. That is the conservative outcome, and the policy's test for `crit` doesn't apply.

Making it critical would also have a real cost. A 3.1 client that predates this amendment would refuse the first version listing `requires` (`unsupported-critical`), and by rule 3 of §3.3 would accept nothing newer. It would stop applying removals, never see new members, be unable to join any circle whose history ever carried a floor, and keep re-requesting versions it refuses. The 14-day grace wouldn't help, because that refusal happens when the version arrives, not at `from`.

If a future floor needs to restrict something, for example a floor that gates authorisation, it will be a new critical field with its own RFC.

### 5.2 Two steps

Clients from before protocol 3.1 refuse any unknown field, `requires` and the new proposal field included. 3.1 clients ignore them. The two steps exist for the pre-3.1 clients, for the owner's own key-holding devices (section 4.5) and for admins' proposals:

1. **Step 1 (accept and display).** Clients parse `requires`, keep it, show it, compute below/unknown members and show the notices, and advertise the status cap `circle.requires.v1`. They never emit `requires`, and an owner's client refuses `op: "requires"` proposals with "not yet: this release only reads floors". The cross-version matrix gains checks that a step-1 client accepts a version carrying `requires` (from a test fixture), refuses one that lists it in `crit`, and that the previous two releases accept such a version and ignore the field.
2. **Step 2 (emit), once the previous two releases include step 1.** The owner's client may sign a version with `requires`, with the checks in section 4.5 and one guard: it refuses while any member standing in the circle is known to be below protocol 3.1, naming them. There is no force path. It lists members whose protocol minor is unknown as a warning. The matrix is run with step 2 on (`--new-env`) against both previous releases before the release that turns it on.

### 5.3 Relays and test vectors

Relays don't change. Circle versions aren't parsed by relays beyond the envelope (§5). New test vectors go in `packages/core/src/v3/testdata`:
- a version with a valid floor, and one with an unknown `x:` feature (accepted);
- each malformed shape: `requires` in `crit`, empty `features`, unsorted or duplicate features, `from` out of range, an unknown key;
- a raise that breaks the 14-day rule, an unchanged floor with a changed `from`, a raise whose `iat` is earlier than its parent's, and a mixed change that counts as a raise;
- floor-state sequences: a lowering during the grace keeps T; a raise while an earlier floor is in effect keeps it until T; a late delivery gets t_first + 14 days;
- proposals: a valid floor, `null`, a malformed object, and a stale one.

## 6. Security and privacy analysis

- **Surprise cut-off.** A floor never removes a member. Because `requires` isn't critical, a client that doesn't understand it keeps following the circle's chain, so removals, new members and joins keep working on it. Enforcement starts no earlier than 14 days after each receiver first saw the floor, whatever the signer claims in `iat` or `from`, and relaxations never advance it. The remaining exposure is pre-3.1 clients, which refuse any unknown field: the step-2 guard refuses while a member is known to be one, but can't see unknown members and doesn't bind a hostile signer. A pre-3.1 client also can't join a circle whose history carries `requires`; pre-3.1 clients are pre-release and outside the compatibility window.
- **Downgrade.** There is no maximum. A floor can't lower anyone's protocol, and a client never disables a feature because of one. A replayed older version with a lower floor is not accepted: versions are chained and never skipped (§3.3 rule 3), and sibling rules decide forks as today. Removing a floor is immediate, but a floor grants no security property in the first place.
- **Denial of service by the owner or an admin:**
  - The owner's client refuses a floor that no released client meets, but that check binds only an honest signer (section 4.5). A hostile owner key can sign `proto: "3.999"` or invented features. Its effect is bounded: such a floor appears in doctor only (unknown minor) or as "unknown requirement set by <owner>" (`x:` caps), notices carry no peer links or text, are rate-limited and can be suppressed per circle, and nothing is ever refused or removed.
  - A floor can't be used to lure people to a fake update: the notice names the owner and points only to the client's built-in update instructions.
  - Raising the floor again and again can't make a notice storm (notices are rate-limited per circle), and each raise restarts the receiver-side grace, so enforcement can't be advanced.
  - An admin can only propose, and `requires` proposals always wait for the owner's approval. Concurrent proposals are made stale by any floor change after their `base`.
- **Denial of service by a member:** a member can't set a floor. A member that hides its caps is "unknown", and is neither penalised nor counted as meeting the floor. Old evidence expires after 30 days, so a long-gone device doesn't hold its user "below".
- **Self-asserted caps.** Caps come from a member's own statuses and `dinfo`. A member that claims caps it doesn't have only hurts itself (it gets the full form of a feature it can't use). "Meets the floor" is not an assurance about a member's client and must never be used as one.
- **Metadata to members.** Members learn nothing new: caps are already in statuses and opt-in `dinfo`. The admin view uses only evidence the viewer already holds; `--would-require` makes enumeration convenient but reveals nothing the viewer couldn't compute. The floor itself is visible only to whoever holds the circle chain, the same audience as the member list. No exact client version is published.
- **Metadata to relays.** After enforcement, the outer `kind` and size of circle-wide sends can differ between members who meet the floor and members below it, so a relay can tell which recipients' devices are below the floor. This adds to the metadata relays already see ([threat model](../security/threat-model.md), "What each party can see"). It is limited by registering fallbacks under the same outer kind and size class where the feature allows (section 4.4), and today's registry has no circle-wide caps at all. Per-user features already differ per recipient today, with or without a floor. The floor is never shown to non-members (open question 3).
- **Prompt-injected agents.** The notice text is fixed by the client, never peer-supplied, and the circle name in it passes the usual peer-text sanitiser. Agents can't set, propose or approve floors, or run `--would-require`: these are refused from an agent session like other circle changes. A person can suppress the session-start notice per circle, which keeps peer-named text out of a model's context.
- **Fail-closed behaviour.** A malformed `requires` (shape, `crit`, the 14-day rule, a backdated raise) makes the version `malformed` (refused), and the reference owner's client never signs one. An unknown feature makes the receiver show itself as below the floor (a notice), never a refusal. A stale or missing status means "unknown" (no notice about others).

## 7. Alternatives considered

- **A critical field (the first draft of this RFC).** Listing `requires` in `crit` would make older clients refuse floor versions and stall their chains: no removals applied, no new members, no joins, and repeated re-requests (section 5.1). Owner-side guards can't fix that, because they don't bind a hostile signer. Rejected on security review (#37).
- **A protocol version bump per circle (`p2p/v4` circles).** Too coarse: the goal is to align features within v3, not to fork the network.
- **Automatic removal of members below the floor.** Simple to enforce, but it is the surprise cut-off this RFC exists to prevent.
- **Holding messages for members below the floor.** An unbounded sender-side hold is a resource-exhaustion vector, and its limits would diverge between implementations. Floors use registered fallbacks only.
- **Floors in each member's identity document.** These would be per user rather than per circle, and nobody would be accountable for them.

## 8. Open questions

1. Should the 14-day grace be configurable upward per circle (larger organisations)? The proposal: a minimum of 14 days, with the owner free to set `from` later.
2. Should the Claude mod's session-start notice for a member below the floor be suppressible per circle? **Answered: yes.** Doctor still shows it (section 4.3).
3. Should an open circle (P2) display its floor on the link landing page, so joiners know before joining? **Answered: no.** The floor is a member-only detail, like the member list. A joiner sees it in doctor after joining, during the joiner's own 14-day announced period.

## 9. Revision history

**2026-11-19: revised after the security review on [#37](https://github.com/ix-infrastructure/Peer2Peer/issues/37).**

- **H1.** `requires` is now informational and MUST NOT be in `crit`; listing it there is `malformed`. Section 5.1 explains why (it narrows no authorisation, and ignoring it is conservative). Step 2's guards that existed only for the `crit` cost are gone; the two-step rollout remains for pre-3.1 clients, with the emit guard "refuse while any standing member is known to be below protocol 3.1". A future authorisation-gating floor would be a new critical field with its own RFC.
- **H2.** Receivers enforce from max(`from`, t_first + 14 days). Relaxations apply at once but keep the pending enforcement time, so lowering never moves enforcement earlier. A raise whose `iat` precedes its parent's is `malformed` (chosen over "ignored" so later comparisons stay unambiguous).
- **M1.** `requires` proposals are never applied automatically. The proposal field is defined (`requires: {proto, features} | null`), and staleness is keyed on the floor.
- **M2.** The owner's client refuses to sign unless all its key-holding devices advertise `circle.requires.v1`. Raise, relaxation and unchanged are decided against `ver − 1` on the accepted chain; a floor re-applied after a fork is a raise; transfers carry `requires` and `from` unchanged.
- **M3.** Section 4.4 is now a table per cap. Holding is removed. A `proto`-only floor is notice-only. `receipts.v1` and `invite.circles.v1` are dropped, `agents.v1` is added (notice-only), and the `projects.v1`/`not_shared` interaction is explained. The motivation now says that `agents` and extension state are already per recipient. Unknown `x:` caps are shown as "unknown requirement set by <owner>".
- **M4.** Notices carry no peer links or text; floors above any known minor appear in doctor only; section 6 says the at-signing check doesn't bind a hostile signer.
- **M5.** Section 6 states what relays can observe after enforcement. Circle-wide fallbacks use the same outer kind where possible. Open question 3 is answered "no".
- **L1–L4.** Parse rules tightened (features, sorting, `from` range, mixed changes count as raises, an earlier floor stays in effect until the new one's time, "unchanged" after parsing). Evidence order: live status overrides older `dinfo`, and evidence older than 30 days is ignored. The floor verbs and `--would-require` are agent-guarded. The session-start notice can be suppressed per circle (open question 2: yes). Notice periods are computed locally. The admin view uses only evidence already held.
