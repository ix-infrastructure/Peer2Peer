# RFC 0002: Circle version floors (version alignment)

| | |
|---|---|
| **Status** | Proposed (open for comment; at least 14 days per GOVERNANCE.md). Nothing here is implemented. |
| **Date** | 2026-11-05 |
| **Applies to** | [protocol.md](../protocol.md) v3 draft 3 (protocol 3.1), §3.3 circle versions, as an additive amendment with a two-step rollout per [compatibility.md](../compatibility.md) |
| **Discussion** | the RFC issue linked from the PR that adds this file |

Words in capitals (MUST, SHOULD, MAY) are used as in RFC 2119. Section signs (§) without a file name point into [protocol.md](../protocol.md).

## 1. Summary

A circle can carry an optional, signed **floor**: the oldest protocol minor and the feature caps its members' clients should have. The field is `requires: {proto, features, from}` in the circle version (§3.3). It is set by the owner, or proposed by an admin and applied by the owner's client like any other change.

- **A floor only.** It names a minimum and never a maximum, so nothing can use it to make a client downgrade.
- **It never removes anyone.** A member below the floor stays a member. It is told, in every front end, that the circle needs a newer Peer2Peer. It keeps being sent everything its client can handle.
- **Announced before it's enforced.** A floor takes effect at `from`, at least 14 days after the version that sets it. Until then it only produces notices.
- **Critical.** Because enforcement restricts what the circle sends to members who lack a feature, `requires` is listed in `crit`. Clients that don't understand it therefore refuse the version, and section 6 shows how the rollout keeps that from cutting anyone off.

Feature use inside a circle stays decided per message by positive evidence (`peerSupports`, [compatibility.md](../compatibility.md)), now applied per circle. The floor adds one thing: after `from`, a circle-wide feature listed in the floor is used even when a member below the floor lacks it. That member gets the documented fallback for it, or is held, never a broken message.

## 2. Motivation

The compatibility policy keeps every release interoperating with the previous two, and features roll out in two steps so older clients never see what they would reject. That works peer to peer. A circle is different: a feature that only makes sense circle-wide stays off for everyone as long as one member's client lags. Examples are status `agents`, extension state, or a future sealed-sender or padding mode from RFC 0001. Today:

- **Nobody can see the lag.** An owner has no list of which members hold the circle back, and a lagging member isn't told.
- **The weakest client decides forever.** One device that is never updated keeps a circle-wide feature off for good.
- **There is no way to say "this circle needs X".** That includes security properties a team wants for all of its members (for example "only clients with project boundaries", `projects.v1`).

Version alignment gives the circle a signed, visible statement of what it expects, a grace period to get there, and a clear notice to whoever is behind. It doesn't change who is a member or what anyone may send.

## 3. Goals and non-goals

### 3.1 Goals

- **G1.** Members learn each other's protocol minor and caps from what is already published (status `caps`, `dinfo`). No new metadata is involved.
- **G2.** A circle-wide feature is used only when every live member supports it (`peerSupports({all})`, per circle), or when the circle's floor, in effect, lists it.
- **G3.** A member below the floor is told, in `p2p doctor`, `p2p tui`, the Claude mod and the Codex bridge: "this circle needs Peer2Peer with proto ≥ 3.x and <features>; update". It stays a member and is still sent everything it can handle.
- **G4.** The owner and admins can list members who are below the floor, or would be below a proposed one.
- **G5.** A floor can't cut members off by surprise, force a downgrade, or serve as a denial of service.

### 3.2 Non-goals

- **No maximum, pinning or downgrade.** Clients never run an older protocol because a circle says so.
- **No automatic removal.** Removing a member stays a deliberate `propose remove` by a person.
- **No exact versions on the wire.** A floor names protocol minors and feature caps, never a client version string, matching the status rule against exact versions (compatibility.md "Where it's advertised").
- **No relay involvement.** Relays don't read or enforce floors.

## 4. Proposed spec text (§3.3 amendment)

### 4.1 The field

A circle version MAY carry:

```
"requires": { "proto": "3.<minor>", "features": ["<cap>", ...]?, "from": <s> }
```

- `proto`: a string `"3.<minor>"`, where `<minor>` is a decimal integer from 1 to 999, no leading zeros. It means "a client whose status caps include `proto.3.<m>` with m ≥ minor".
- `features`: optional, 1 to 8 distinct status caps, each matching the status caps charset (§4.3), sorted ascending. Each MUST be a cap the reference client registers as **floorable** (section 4.4). A receiver that doesn't know a listed feature treats itself as below the floor (section 4.3). It does not refuse the version.
- `from`: when enforcement begins, as Unix seconds. It MUST be at least `iat + 14 × 86400` in the version that first sets or raises the floor. A version that only repeats an unchanged floor carries the same `from`.
- When present, `requires` MUST appear in the version's `crit`.
- Any other shape makes the version `malformed`.

**Raising, lowering, removing:**
- *Raising* means a higher `proto`, or any added feature. It needs a fresh `from` that satisfies the 14-day rule against the raising version's `iat`.
- *Lowering or removing* takes effect at once, because it only relaxes: a lowered floor carries `from = iat`.
- A version that keeps `requires` unchanged MUST keep `from`. A receiver that sees an unchanged floor with a different `from` treats the version as a raise and applies the 14-day rule. If the rule fails, the version is `malformed`.

**Who sets it:** the owner signs it, as every version (§3.3). An admin sets it through a proposal (`op: "requires"`, arg the JSON above without `from`), which the owner's client applies with `from = now + grace`. When `circle hold` is on, the proposal waits for the owner's approval, as other proposals do.

### 4.2 Discovery

- A member's capabilities are read from the evidence the client already holds, in the order of `peerSupports`:
  1. the member's `dinfo` entries;
  2. the member's live statuses;
  3. their latest statuses.
- A member **meets** the floor when at least one of its devices shows `proto.3.<m>` with m ≥ the floor's minor and every listed feature. A member **is below** the floor when every device the client knows of shows evidence of something missing.
- With no evidence at all, the member is **unknown**. It is never counted as below, so a silent member gets no notice from others, and its own client decides for itself (section 4.3).
- `peerSupports({all})` gains a circle scope: `{all, cid}` asks the question of every live session of every member that stands in the circle. A circle-wide send (status `agents` to a circle audience, extension state) uses it, as `{all}` is used per user today.

### 4.3 What clients do

**A member's own client:**
- When its own caps don't meet a floor in a circle it stands in, it shows "<circle> needs Peer2Peer with proto ≥ 3.x [and <features>]; update", from the version's arrival on. The wording changes on and after `from` ("…is in effect").
- The notice appears in `p2p doctor`, `p2p circle ls`/`members`, `p2p tui`, the Claude mod (`/peers doctor`, the session-start notice) and the Codex bridge (`p2p codex held` and its MCP `doctor`). It shows at most once a day per circle, outside doctor.
- Nothing else changes: it keeps its membership, its join statement and every feature it has.

**Every other member's client**, for circle-wide features (anything decided with `{all, cid}`):
- **Before `from`, or with no floor:** a feature is used only when every live member supports it (G2), as today.
- **On and after `from`:** a feature listed in the floor is used even when a member below the floor lacks it. That member gets the feature's documented fallback (for extension kinds, the plain `fallback`; for state kinds, nothing), or the message is held for it with a notice. A send to it never fails or degrades silently.
  - Features not listed in the floor keep the `{all}` rule.
  - Sends to a single member (direct messages, receipts `{sid}`) are unaffected: they follow that member's own evidence.
- A floor never makes a client refuse an envelope, a status or a membership statement from a member below it.

**Admin view:**
- `p2p circle members <cid>` and `p2p doctor` show the floor and its `from`, and list each member who is below it or unknown, as "below: proto 3.1, missing receipts.v1".
- `p2p circle members <cid> --would-require '<json>'` shows the same for a proposed floor before anyone sets it.

### 4.4 Floorable features

Only caps whose absence has a defined fallback may be listed. The initial registry is `receipts.v1`, `projects.v1`, `invite.circles.v1` and `xstate.v1`. Adding one is a spec PR under §8-style first-come registration, with its fallback stated.

## 5. Compatibility and rollout

### 5.1 The crit problem, and why it's still the right choice

`requires` restricts what the circle sends to members below it (section 4.3), so the compatibility policy says it must be critical. The cost: a client from before this amendment refuses a version that lists `requires` in `crit` (`unsupported-critical`). By rule 3 of §3.3 it then accepts nothing newer. It is not removed, and its own sends still work, but it stops following the circle's changes (new members, renames, removals). Clients from before protocol 3.1 refuse any unknown field, `requires` included. The rollout below makes sure no member is in that position by surprise.

### 5.2 Two steps

1. **Step 1 (accept and display).** Clients parse `requires`, keep it, show it, compute below/unknown members and show the notices, and advertise the status cap `circle.requires.v1`. They never emit `requires`, and admins' `op: "requires"` proposals are refused with "not yet: this release only reads floors". The cross-version matrix gains a check that a step-1 client accepts a version carrying `requires` (from a test fixture) and that the previous two releases are unaffected by everything else.
2. **Step 2 (emit), once the previous two releases include step 1.** The owner's client may sign a version with `requires`, with these guards:
   - it refuses while any member standing in the circle is known not to advertise `circle.requires.v1`, naming them;
   - for unknown members it asks for explicit confirmation;
   - `--force-after-grace` lets an owner go ahead after a 14-day notice period in which every member was told "this circle will need clients that understand version floors".
   - The matrix is run with step 2 on (`--new-env`) against both previous releases before the release that turns it on.

### 5.3 Relays and test vectors

Relays don't change. Circle versions aren't parsed by relays beyond the envelope (§5). New test vectors go in `packages/core/src/v3/testdata`: a version with a valid floor, each malformed shape, a raise that breaks the 14-day rule, and an unchanged floor with a changed `from`.

## 6. Security and privacy analysis

- **Surprise cut-off.** A floor never removes a member, and enforcement starts at least 14 days after the version that announces it. The members below it are told for that whole time, and the owner sees the list before signing. The crit cost is bounded by the step 2 guards in section 5.2.
- **Downgrade.** There is no maximum. A floor can't lower anyone's protocol, and a client never disables a feature because of one. A replayed older version with a lower floor is not accepted: versions are chained and never skipped (§3.3 rule 3), and sibling rules decide forks as today.
- **Denial of service by the owner or an admin:**
  - A floor that no released client meets is refused at signing: the owner's client checks `proto` ≤ its own minor and that every feature is floorable and one it has. Receivers that don't know a feature only show a notice.
  - Raising the floor again and again can't make a notice storm: notices are rate-limited per circle, and each raise restarts the 14-day grace, so enforcement can't be advanced.
  - An admin can only propose; the owner applies, and with `hold` on, approves.
- **Denial of service by a member:** a member can't set a floor. A member that hides its caps is "unknown", and is neither penalised nor counted as meeting the floor.
- **Metadata.** Members learn nothing new: caps are already in statuses and opt-in `dinfo`. The floor itself is visible only to whoever holds the circle chain, the same audience as the member list. No exact client version is published.
- **Prompt-injected agents.** The notice text is fixed by the client, never peer-supplied. The circle name in it passes the usual peer-text sanitiser. Agents can't set floors: `op: "requires"` is a person's action, refused from an agent session like other circle changes.
- **Fail-closed behaviour.** A malformed `requires` makes the version `malformed` (refused). An unknown feature makes the receiver show itself as below the floor (a notice). A stale or missing status means "unknown" (no notice about others).

## 7. Alternatives considered

- **Advisory, non-critical field.** Older clients would ignore it and keep following the chain, which avoids the crit cost. But an older client would then ignore a restriction the issuer meant, which is exactly what the compatibility policy forbids for restricting fields. It also couldn't support floors that carry security properties later. Rejected, but kept as the fallback if review finds the step 2 guards insufficient.
- **A protocol version bump per circle (`p2p/v4` circles).** Too coarse: the goal is to align features within v3, not to fork the network.
- **Automatic removal of members below the floor.** Simple to enforce, but it is the surprise cut-off this RFC exists to prevent.
- **Floors in each member's identity document.** These would be per user rather than per circle, and nobody would be accountable for them.

## 8. Open questions

1. Should the 14-day grace be configurable upward per circle (larger organisations)? The proposal: a minimum of 14 days, with the owner free to set `from` later.
2. Should the Claude mod's session-start notice for a member below the floor be suppressible per circle?
3. Should an open circle (P2) display its floor on the link landing page, so joiners know before joining?
