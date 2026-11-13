# RFC 0003: Shared team graph

| | |
|---|---|
| **Status** | Draft (2026-11-12). The CEO decided §13.1 on 2026-11-12 (all as recommended, plus the operator and pricing scope in D1–D2). Not yet accepted: the Ix Pro API contract (§13.2) comes first, and §13.3 stays open. |
| **Date** | 2026-11-12 |
| **Applies to** | [protocol.md](../protocol.md) v3 draft 3: one additive, Ix-free field on circle versions (§9.1). Everything else is in `packages/p2p` and `packages/ext-ix`. |
| **Epic** | [#41](https://github.com/ix-infrastructure/Peer2Peer/issues/41), piece 3 ("Shared graph"), with piece 5 (project boundaries apply to graphs) and piece 6 (an honest encryption story) |
| **Comes after** | piece 2, graph memory in the local graph (shipped in v0.1.1) |

Words in capitals (MUST, SHOULD, MAY) are used as in RFC 2119. Section signs (§) point into this RFC; "protocol §n" points into [protocol.md](../protocol.md).

## 1. Summary

Today every graph target is `local` (concepts.md, "Graph targets"; threat-model.md, "Graph targets (Ix)"). Agents in a circle receive each other's pushed events (statuses, footprints, notes), but nothing durable is shared that an agent can *query*.

This RFC proposes a **shared graph per circle**: an Ix memory layer reached over https, hosted by Ix Pro or self-hosted, or run by anyone whose backend speaks the same open API (decision D1), that the members of one circle write their shared work into and read from. Protocol and client support are free and open source, and so is self-hosting; hosting by Ix Pro is a paid Ix Pro feature (D2).

1. **Binding.** A circle names at most one shared graph, in an owner-signed field of its circle version (§5). It is versioned and hash-chained with the circle, and only the owner changes it. The field is generic (`x`, namespaced attributes); core validates its shape and knows nothing about Ix.
2. **Consent, twice.** The owner's binding is an offer. Nothing is written until a member **enrolls** on their own device (§6): they see who operates the graph, that it holds plaintext, and what will be written, and they type yes.
3. **The chokepoint decides.** `graphTarget()` in `packages/p2p/src/projects.ts` returns `{kind: "shared", circle, endpoint}` only for work whose every project is shared with that one circle, and only when this device is enrolled in that circle's current binding (§7). Every other case stays `local`, exactly as today.
4. **Per-member credentials.** Each member holds their own token for that graph, issued by the operator, with only the scopes the writes and reads need (§8). It is never derived from Peer2Peer keys, never in the environment, and never shown to an agent.
5. **What is written.** The same records as local graph memory (session record, start and end, status lines, edited files), now also to the shared graph; never message bodies (§10).
6. **Honest about plaintext.** Relays see ciphertext. The shared graph's operator reads everything written to it. `p2p doctor`, `p2p project show` and the enrollment prompt say so, and "local only" stays the default (§11).
7. **Fail local, never elsewhere.** If the graph is down, revoked or rebound, writes queue (bounded) or are dropped and counted. They are never redirected to another graph (§12).

## 2. Motivation

- **Pushed events are not memory.** A footprint lives 600 s. A status line is replaced by the next one. An agent that joins at 3 pm can't ask "what did the team's sessions on `auth/*` do this morning, and why?" Today the answer exists only in each person's local graph, which nobody else can reach.
- **Every member's agent should see the same team context.** Piece 4 of the epic ("each live event links to graph nodes, so an agent can pull full context on demand") needs a graph the recipient can actually open. A link into the *sender's* local graph is useless to the recipient.
- **The boundary is already built.** Piece 5's chokepoint shipped with v0.1.1. Every `ix` call already resolves a target, and the `shared` arm of `GraphTarget` exists, with an empty `SHARED_GRAPHS` registry. This RFC defines what may fill that registry, and under which rules.

## 3. Goals and non-goals

### 3.1 Goals

- **G1. One circle, one graph.** A circle names at most one shared graph at a time. A project shared with circle A writes to A's graph and nowhere else.
- **G2. Private stays private.** A private, unmapped, repository-private (`.p2p-private`) or not-yet-bound project never writes to, or reads from, any shared graph. This holds for every session that ever touched such a project (the ceiling is sticky, as today).
- **G3. Opt-in on both sides.** The owner offers a graph; each member enrolls on each device. Neither alone is enough.
- **G4. Least-privilege, revocable credentials** per member, per graph, never derived from Peer2Peer identity or device keys.
- **G5. Removal works.** A member who leaves or is removed stops writing at once (an honest client) and loses access once the operator revokes their credential (any client), and the owner's device says until when that hasn't happened.
- **G6. Honesty.** The person can always see which graph each project writes to, who operates it, and that the operator reads plaintext.
- **G7. Core stays Ix-free.** No Ix code or Ix semantics in `packages/core`, the relay or the wire format. Older clients keep working.
- **G8. Fail closed.** Any doubt (binding changed, token rejected, target changed between queueing and writing, a redirect) means *local or nothing*, never *somewhere else*.

### 3.2 Non-goals

- **End-to-end encryption of the shared graph.** The graph must be queryable by the operator's search and graph engine, so it holds plaintext. A client-side-encrypted graph is a different product (§14).
- **Sharing message bodies, peers' statuses, or other people's notes.** Each member's own client writes only its own sessions.
- **Backfilling the local graph into the shared graph.** Enrollment writes new work only.
- **Mapping code into the shared graph.** Ingestion (`ix map`) stays out of Peer2Peer, as today. Whether the shared graph also holds a mapped code graph is the operator's business (§13.2, Q-P11).
- **Sandboxing Ix.** An agent with the person's shell can still run `ix` with the person's own Ix Pro login. Graph targets close Peer2Peer and ext-ix as a route, as today (threat-model.md, "What it doesn't cover").
- **Making Ix Pro required.** A circle with no binding, and a member who doesn't enroll, work exactly as today. A circle may bind to any endpoint that speaks the Ix memory API, including a team's own self-hosted backend (D1).
- **Gating anything on payment in Peer2Peer.** Ix Pro charges for the graphs it hosts (D2). Peer2Peer never checks a plan or a licence; it reaches any compatible endpoint the owner binds.

## 4. Background: what exists today

From reading the code at `main` (3fa4f07):

- **The chokepoint.** `graphTarget(app, {sid, dirs, paths, over}, sharedGraphs = SHARED_GRAPHS)` intersects the session's ceiling, its folders, the process's cwd and every path a call names. `graphTargetOf()` returns `shared` only when every input is shared with a common circle and **exactly one** of those circles has a shared graph (an https endpoint off this machine). Several such circles, people-only shares, or none: `local`. A `shared` result also needs a session a front end registered (its person token).
- **The registry is empty.** `SHARED_GRAPHS` is a constant empty map. Its comment says a later PR fills it "from settled, person-made state. Nothing in the environment, config.json, a repository or a peer's message can add to it." This RFC keeps that promise: the binding is owner-signed circle state, and enrollment is the person's own act.
- **The extension seam.** `ExtContext.graphTarget()` hands ext-ix an `ExtGraphTarget`, whose `shared` arm already has an optional `token`. ext-ix's `checkedTarget()` re-checks the endpoint, `ixEnv()` would pass the token to an `ix` child as `IX_PAT`, and `refuseForTarget()` refuses every call against a shared target today.
- **Graph memory.** `p2p watch` gathers this device's own sessions' statuses and drains them in per-session batches. `drainBatch()` drops any batch whose target isn't local (`not_local`), and re-checks that the ceiling is still shared.
- **Ix Pro, as the open-source CLI sees it.** With Ix Pro installed, `ix note` and `ix session` go to the active cloud org instead of the local backend (the OSS CLI registers its own only when Pro didn't load). Ix Pro's model is a sign-in (`ix login`) to a tenant, and an **org** per graph (`ix org use <org>`). For headless use, Ix Pro accepts a **personal access token** (PAT mode): a bearer token, sent only to one validated https origin, never stored by the CLI, whose org is decided by the server, not the client. PATs are deny-by-default per scope; the documented scopes are `graph:read`, `notes:write` and `sessions:write`, and there is no graph-write (ingestion) scope under a PAT.
- **One API, two backends.** The note and session routes (`POST /v1/note`, `GET /v1/note/{id}`, `GET /v1/notes`, `POST /v1/session`, `GET /v1/session/{nameOrId}/notes`, …) are in the open-source Ix API (`docs/api/openapi.yaml` in the Ix repository), served by the OSS backend and by the hosted one.

## 5. Binding a circle to a graph

### 5.1 Where the binding lives

The binding is an **owner-signed attribute of the circle version** (protocol §3.3). That gives it, for free, everything a binding needs:

- only the owner's identity key signs it, so an admin, a member, a relay or a repository can't set it;
- it is versioned and hash-chained with the circle, so every member converges on the same binding by the existing chain and fork rules (transfers win, lowest `jwsHash` between siblings, freezes on equivocation);
- it reaches every member, and every new member with the full chain, by the existing distribution (protocol §3.3, "Distribution and freshness");
- a former owner can't rewrite it (finality at the latest `transfer`).

The alternatives (an extension envelope from the owner, per-member local config, the identity document) are compared in §14.

### 5.2 The generic field (core)

A circle version MAY carry one new optional field, `x`: a JSON object of **namespaced attributes**.

```
"x": { "<ns>.<name>": <JSON object>, ... }
```

Core checks only the shape:

- at most 8 entries;
- each key matches `^[a-z][a-z0-9_-]*\.[a-z0-9_-]+$`, and its first label is a namespace registered in protocol §8.3;
- each value is a JSON object whose canonical serialisation is at most 1 KiB;
- the whole field at most 4 KiB.

A malformed `x` makes the circle version `malformed`. Core gives the parsed field to the client unchanged and attaches **no meaning** to it: no core rule, authorisation decision, capability or relay behaviour depends on it. That keeps core Ix-free (G7). The reference client exposes the head's attributes to `p2p` (read-only), and an extension reads only its own namespace.

**Not critical.** `x` is not listed in `crit`: a client that ignores it simply never sees a shared graph, so its targets stay local, which is the narrower outcome (compatibility.md, "`crit`": a field that only *adds* an option stays out).

### 5.3 The Ix binding (`ix.graph`, ext-ix)

```json
"x": { "ix.graph": {
  "v": 1,
  "gid": "g_<b32 of 16 random bytes>",
  "endpoint": "https://<operator host>/<path>",
  "graph": "<the operator's id for this graph, ≤128 printable ASCII>",
  "operator": "<display name of who runs it, ≤64 characters>"
} }
```

- **`gid`** names this binding. A binding with a new `endpoint` or `graph` MUST carry a new `gid`. A client that sees the same `gid` with a different `endpoint` or `graph` than it enrolled in treats the binding as invalid: target `local`, and an alert (§7.3).
- **`endpoint`** is normalised as `normalizeSharedEndpoint()` does today: `https`, not loopback, no credentials, query or fragment.
- **`graph`** is the operator's identifier (for Ix Pro, the org; see Q-P1). It is shown, and checked against what the credential is for (§8.3).
- **`operator`** is a label, shown to the person. It is the owner's claim, not verified (the endpoint is what counts).
- **Removing** the attribute (a version without `ix.graph`) unbinds the circle.

### 5.4 Who may change it

- **The owner only** (decision D5), by publishing a new circle version. There is **no** admin proposal op for binding, rebinding or unbinding: pointing a whole team's writes at a server is the owner's decision. An admin's `p2p-circle-op+jws` can't carry it, and the owner's client applies no proposal that would change `x`.
- **The owner's client asks first.** `p2p circle graph set <circle> --endpoint … --graph … --operator …` and `p2p circle graph unset <circle>` are person-only widening commands (the person token, or `yes` at the controlling terminal), like `project share`. An agent can't run them.
- **Rollout gate.** The owner's client publishes a version with `x` only once every member device it knows of advertises cap `circlex.v1` (§9.2), and otherwise says which members are too old.

## 6. Enrolling: the member's consent

A binding is an offer. A member's device writes to the shared graph only after the person **enrolls** that device in that exact binding:

```
p2p ix graph join <circle>      # person-only: token or yes at the terminal
p2p ix graph leave <circle>     # always allowed (narrowing)
p2p ix graph show [<circle>]    # what is bound, enrolled, written, queued, dropped
```

`join` shows, before asking:

- the circle, the binding's `operator`, `endpoint` and `graph`;
- **"Everything written there is plaintext that the operator can read. Relays never see it; the operator does."**;
- what this device will write (§10), per content class, with the defaults;
- that only projects shared with this circle write there, and that nothing already in the local graph is copied.

Then it obtains a credential (§8.2), checks it (§8.3), and records the enrollment:

```
P2P_HOME/cli/graph/<cid>.json  (0600, sealed like the message history)
{ "cid", "gid", "endpoint", "graph", "classes": [...], "token": <sealed>, "principal", "expires", "at" }
```

Enrollment is **per device**: it isn't synced, so a device the person links later is not enrolled until they enroll it. An enrollment is valid only while the circle's held head carries the same `gid`, `endpoint` and `graph`.

## 7. The chokepoint

### 7.1 Filling the registry

`SHARED_GRAPHS` becomes a function of local state, computed by `p2p` on each call (no cache across a change of circle head or enrollment). A circle `cid` maps to an endpoint only when **all** of these hold:

1. the person has joined `cid` on this device and stands in it in the held head (protocol §3.3, "standing");
2. the circle isn't frozen;
3. the held head carries a valid `ix.graph` attribute;
4. this device has an enrollment for `cid` whose `gid`, `endpoint` and `graph` equal the head's;
5. the enrollment's credential isn't marked revoked or expired (§8.4);
6. shared graphs aren't turned off (`"ixSharedGraph": false` in config.json, or `P2P_IX_SHARED_GRAPH=0`; the environment can only turn it off).

Nothing else can add an entry: not the environment, `config.json`, a repository, a peer's message, an extension, or an agent.

### 7.2 Deciding the target

`graphTargetOf()` keeps its rules unchanged. With the registry above, it returns `{kind: "shared", circle, endpoint}` only when:

- every project the call touches (the session's bound projects, its folders, the process's cwd, every path named) is shared, with no `.p2p-private` and no private or unmapped project;
- they all share at least one common circle, and **exactly one** of the common circles is in the registry;
- the session was registered by one of the person's front ends.

Two refinements:

- **People-only and mixed shares.** A project shared with circle A *and* with friend Bob (outside A) still targets A's graph: Bob's audience is the push channel, and A's members are the graph's audience, a subset of the project's audience. The graph never reaches *wider* than the project's circles. (A project shared with Bob only stays local.)
- **Several circles with graphs.** A project shared with A and B, both bound, stays local (today's rule). §13.3 Q-T1 asks whether the person should be able to pick one per project instead.

The target is passed to the extension with the credential (`ExtGraphTarget.token`), and to no one else.

### 7.3 When the binding changes

A new circle head with a different `gid`, an unbound head, a freeze, or the person's own removal or leave makes every target for that circle `local` at the next call. On a `gid` change the client also:

- deletes nothing silently: the old enrollment is kept, marked `stale`, and shown;
- tells the person once (`p2p status`, the mod's toast): "circle *team* moved its shared graph to *operator* (*endpoint*). Run `p2p ix graph join team` to follow it.";
- never re-enrolls on its own, even when the new endpoint is at the same operator.

## 8. Credentials

### 8.1 Principles

- **Per member, per device, per binding.** One credential for one `gid`, held by one device. Never shared between members, never sent over Peer2Peer.
- **Not derived from Peer2Peer keys.** The identity key and device keys never sign, derive or wrap a graph credential. Compromising one never yields the other, and rotating one never requires the other.
- **Least privilege.** Only the scopes the enrolled content classes need: `sessions:write` and `notes:write` to write, `graph:read` to read (Ix Pro's documented PAT scopes). A token with broader scopes (admin, ingestion, billing) is refused at enrollment (§8.3) unless the operator offers nothing narrower (Q-P3).
- **Short-lived and renewable.** The credential expires (Q-P4 proposes 30 days); renewal needs the member's sign-in at the operator, not anything Peer2Peer holds.
- **Never in the environment or argv.** Stored sealed in `P2P_HOME` (as the message history is: a key of its own, 0600). Read only by `p2p`, passed to ext-ix in memory, and used by ext-ix in-process (§8.5). The agent's shell never sees it; [sandboxing `P2P_HOME`](../security/threat-model.md#the-hard-barrier-sandbox-your-agents) keeps it out of an agent's reach.

### 8.2 Getting one

Two ways, in order of preference:

1. **A device-authorisation flow** at the operator (OAuth 2.0 device grant, RFC 8628, or a loopback redirect). `p2p ix graph join` prints a URL and code. The person signs in at the operator, sees "Peer2Peer on device *X* asks for: write sessions and notes, read, in graph *G*, for 30 days", and approves. The token comes back to `p2p` directly. This is what Q-P2 asks Ix Pro for.
2. **Paste a token** the person made in the operator's own UI. `p2p` reads it from the controlling terminal with echo off (or from stdin with `--token-stdin`), never from argv or the environment.

The circle owner never issues members' credentials, and Peer2Peer never carries them.

### 8.3 Checking one

Before saving, `p2p` asks the endpoint who the token is (an introspection route, Q-P5) and refuses unless:

- the token's graph equals the binding's `graph`;
- its scopes are within the allowed set for the chosen classes;
- it isn't expired.

It records the principal id the operator reports (not the token) and the expiry. A token that would work against a **different** graph than the binding names is refused, so a member can't be tricked (or trick themselves) into writing a circle's work into another org.

### 8.4 Revocation

| Event | What the member's own client does | What makes it hold against a dishonest client |
|---|---|---|
| The member runs `p2p ix graph leave` | stops writing at once; asks the operator to revoke the token (self-revocation, Q-P6); deletes it | the operator's revocation |
| The member leaves the circle (`leave` statement) | the same, automatically | the operator's revocation |
| The owner removes the member (a version without them) | the same, as soon as it holds that version | the owner's revocation at the operator (below) |
| The owner unbinds or rebinds the circle | every member's enrollment for the old `gid` stops (§7.3) | the owner revokes or deletes the old graph at the operator |
| The token expires | target local; `p2p doctor` says "renew: `p2p ix graph join`" | expiry at the operator |
| The operator answers 401 | marks it revoked, stops, says so | (the operator already acted) |

**Removal needs the operator.** Circle membership lives on members' devices; the operator doesn't know it. So the owner's device keeps the graph's access list in step with the circle:

- At enrollment, the member's client sends the owner an `x:ix.graph-enrolled` envelope (§9.3): `{cid, gid, principal, expires}`. Information only: it grants nothing, and it never carries the token.
- When the owner publishes a version that removes a member (or applies their `leave`), and the circle is bound, the owner's client **revokes that member's principal at the operator**, with the owner's own administrative credential for the graph (Q-P7), or, if it has none, tells the owner to do it and keeps saying so in `p2p doctor` ("*bob* left *team* 3 days ago and can still read its shared graph").
- Q-P8 asks whether the operator can instead accept a signed membership list from the owner, so access follows the circle with no per-member calls.

**What revocation can't undo.** Anything a removed member already read, or wrote, stays where it went. `p2p ix graph show` and the docs say so plainly.

### 8.5 How ext-ix uses it

ext-ix writes and reads the shared graph **over HTTP, in-process**, for a fixed set of routes, rather than through an `ix` child:

- `POST /v1/session`, `POST /v1/note` (writes); `GET /v1/notes`, `GET /v1/note/{id}`, `GET /v1/session/{nameOrId}/notes`, `POST /v1/search` (reads; Q-P9);
- `Authorization: Bearer <token>`, only to the target's endpoint (origin and path prefix), `redirect: "error"`, TLS validated, a deadline per call;
- the body built by ext-ix (text never on argv, as today).

Why not run `ix` with `IX_PAT`: the token would sit in a child process's environment (readable by the same user, `/proc/<pid>/environ` on Linux, for the life of the call); it would require Ix Pro to be installed; and Ix Pro's routing (config.yaml, remote runners) is exactly what the local-target guard works to close. A short allowlisted HTTP client is easier to audit. `ixEnv()` stops passing `IX_PAT` (that branch is unused today), and `refuseForTarget()` keeps refusing every `ix` command against a shared target.

## 9. Wire and protocol impact

### 9.1 Core: one generic field

The only protocol change is `x` on circle versions (§5.2), added to protocol §3.3 as a draft 3 amendment. Core stays Ix-free: it validates the shape and the namespace registry, and nothing else. No change to envelopes, kinds, caps, relays, rosters or authorisation (protocol §4.2). Relays never see circle versions in the clear (they are end-to-end encrypted `circle` envelopes), so relays are unaffected.

### 9.2 Rollout of the field (two steps)

Clients before protocol 3.1 refuse any unknown field in a signed object, so a circle version carrying `x` would be `malformed` to them, and they would stop accepting the circle's head. Hence the usual two steps (compatibility.md, "Policy"):

1. **Accept.** A release parses `x` (§5.2) and advertises cap `circlex.v1` in its status `caps`. It never emits `x`.
2. **Emit.** From two releases later, the owner's client may publish a version with `x`, and only when every member device it has a status from advertises `circlex.v1`. It names the members whose devices don't, and the owner may publish anyway with `--force-old-members` (those members' clients then stop following the circle until they update; the CLI says so).

### 9.3 Extension kinds (ext-ix, the existing seam)

- **`x:ix.graph-enrolled`** (member → owner, not a state kind): `{cid, gid, principal, expires}`, with fallback "enrolled in the shared graph of *circle*". The owner's ext-ix keeps it in its own store, for §8.4. Receiving it changes no authorisation.
- **No new kind is needed for reading.** Piece 4 will add graph node links to live events; those need the recipient to be enrolled in the same binding to open, and fall back to the event's own text otherwise.

It is registered under the existing `ix` namespace in protocol §8.3 and specified in `packages/ext-ix/SPEC.md`.

### 9.4 Extension contract

- `REQUIRED_GRAPH_TARGETS` goes to `2` for **shared** targets: `p2p` gives a shared target only to an ext-ix that declares `graphTargets: 2` (it understands shared targets, the in-process HTTP client and the enrollment store). An older ext-ix keeps getting only local targets, so it can never be handed a token.
- `ExtContext` gains read-only `circleAttr(cid, key)` for the extension's own namespace, and nothing else about circles.

## 10. What is written

### 10.1 Content classes

Each enrollment chooses classes. The defaults (decision D3): `sessions`, `status`, `files` and `notes` on; `footprints` off.

| Class | What | Where it comes from | Default |
|---|---|---|---|
| `sessions` | a session record `p2p-<sid>` with label, repository (normalised remote, no credentials) and branch; its start and its end | this device's own sessions' statuses | on |
| `status` | each new status one-liner | the same | on |
| `files` | the repo-relative files it edited, as its status lists them | the same | on |
| `notes` | notes the person (or the session's front end, on the person's behalf) publishes to the graph: `p2p ix note --to-graph` | an explicit command | on |
| `footprints` | a summary of the session's footprint at its end (changed symbols, one hop downstream) | ext-ix's footprint state | **off**, and v1 has no way to turn it on (D4) |

Every record keeps today's framing: tagged `finding`, first line "Recorded by Peer2Peer (agent-generated, untrusted)", `--actor=p2p:<address>` (a label: the operator's principal is the real attribution, Q-P10).

### 10.2 What is never written

- message bodies, in or out (message history stays in its own encrypted store);
- peers' statuses, footprints or notes (a peer's note reaches a graph only through that peer's own enrollment, or the person's `p2p ix import` into their **local** graph, as today);
- other devices' sessions (each device writes its own);
- anything from a session whose ceiling is private, or whose target isn't this circle's graph, at the time of writing (§10.3);
- anything from before enrollment.

### 10.3 The pipeline

Graph memory keeps its shape. What changes in `drainBatch()`:

- The **local** write stays exactly as today (piece 2; decision D7): the person's local graph still gets every shared session's record. "Local only" stays first class, and the local copy is what survives an outage.
- A **second, per-circle queue** takes the same items when the session's target at gather time is `shared` for an enrolled circle. Each item carries the `(cid, gid)` it was gathered for.
- At drain, the target is computed again (as today). The batch is written only if the target is still `shared` with the **same `cid` and `gid`** and the ceiling is still shared. Otherwise it is dropped and counted (`target_changed`, `not_shared`): never written to the new target, never to local in its place (local already has it).
- The queue holds at most 256 items per circle, retries with backoff for at most 24 h, then drops and counts (`unreachable`).

## 11. Honesty: what the person sees

- **`p2p project show`** prints each project's target: `graph: local only (http://localhost:8090)`, or `graph: the shared graph of circle team, run by <operator> (<endpoint>): plaintext the operator can read`.
- **`p2p doctor`** adds, per bound circle: enrolled or not, the operator and endpoint, "plaintext readable by the operator", the classes written, the credential's expiry, items written, queued and dropped by reason, and (on the owner's device) removed members whose access isn't revoked yet.
- **`p2p session show <sid>`** says which graph a session writes to, and why (the same `why` strings as today for local).
- **The front ends.** The mod and the Codex bridge show once per session, when its target first becomes shared: "This session's records go to *team*'s shared graph (*operator*), which can read them." The status line can carry the target.
- **Docs.** concepts.md ("Graph targets", "Graph memory"), threat-model.md (§12 additions below), and the README's privacy summary say: relays see ciphertext; a shared graph's operator reads plaintext; nothing goes there unless the circle's owner bound it and you enrolled.

## 12. Failure modes

| Failure | Behaviour |
|---|---|
| Graph unreachable, 5xx, timeout | queue (bounded), retry with backoff ≤ 24 h, then drop and count. Reads fail with `graph_unreachable`. The local write is unaffected. Never redirected. |
| 401 | credential marked revoked; shared writes stop for that circle; doctor says to re-enroll. |
| 403 on one route | that class stops (counted `scope`); the others go on. |
| A redirect (3xx) | refused (`redirect`), counted; never followed, so the token never reaches another origin. |
| TLS error | refused, counted. No downgrade, no "insecure" switch. |
| Binding changed (new `gid`), unbound, circle frozen | target local at the next call; queued items for the old `gid` dropped (`target_changed`); the person told once (§7.3). |
| The session turns private, or a new project narrows it | target local; queued items dropped (`not_shared`). |
| Two bound circles in common | local (today's rule), with that reason in `session show`. |
| Enrollment store unreadable or tampered | no shared targets at all; doctor says why. |
| An older ext-ix | only local targets (§9.4). |
| Clock skew | expiry is the operator's; a local "expired" is advisory and only ever narrows. |

## 13. Decisions and open questions

### 13.1 Decisions (CEO, 2026-11-12)

The CEO decided the questions put to them in the first draft. The design text above already reflects each decision.

- **D1. Operators: any endpoint that speaks the Ix memory API.** A circle may bind to Ix Pro's hosted graph or to a self-hosted Ix backend behind https, or to any other backend that implements the open note and session API. The `ix.graph` attribute names an endpoint, not a vendor, and Peer2Peer hard-codes no operator (§5.3).
- **D2. Pricing.** Ix Pro charges for hosting a shared graph. Protocol support, the client and ext-ix code, and self-hosting stay free and open source. Peer2Peer enforces no plan: whatever the operator charges is between the operator and the team, and "paid features never gate the network" holds (§3.2).
- **D3. Default content classes:** `sessions`, `status`, `files` and `notes` on at enrollment; `footprints` off (§10.1).
- **D4. No footprints in the shared graph in v1.** Revisit with piece 4, and then only for circles whose footprints are already `names=plain`.
- **D5. Owner only.** Only the circle's owner binds, rebinds or unbinds its graph. There are no admin proposals for it (§5.4).
- **D6. The core amendment.** The binding is the generic, Ix-free `x` field on circle versions (§5.2), not an extension envelope (§14, B).
- **D7. The local copy stays.** A session that writes the shared graph also keeps writing the person's local graph, always (§10.3).

The Ix Pro scope names (`graph:read`, `notes:write`, `sessions:write`) may be named in this public RFC.

### 13.2 For the Ix Pro team (the API contract, settled before implementation)

- **Q-P1. Graph unit.** Is one circle's graph one **org**, or a **workspace** (or another unit) inside an org? Can one team run several circles' graphs under one billing account without their data mixing?
- **Q-P2. Device-authorisation flow.** Can a signed-in org member obtain a PAT for one org through a device grant (RFC 8628) or loopback redirect, with a consent screen that names the scopes, the org, the expiry and a client label?
- **Q-P3. Scopes.** Are `sessions:write`, `notes:write` and `graph:read` the right set, or should there be a narrower scope (for example writes limited to sessions and notes whose actor starts with `p2p:`, with no supersede or retract of others' notes)? Is there, or will there be, a `graph:write` scope, and should a Peer2Peer token ever hold it? (This RFC assumes not.)
- **Q-P4. Expiry and renewal.** PAT lifetime (30 days proposed), renewal without a new consent, and whether the operator can force a shorter one per org.
- **Q-P5. Introspection.** A route that, given the bearer token, returns its org (graph), scopes, expiry and principal id, without revealing anything secret, so `p2p` can check a token before saving it (§8.3).
- **Q-P6. Self-revocation.** A route for the token's holder to revoke it.
- **Q-P7. Admin revocation.** A route for an org admin to list tokens by principal and revoke them, and the scope an admin's own credential needs for that (kept off members' tokens).
- **Q-P8. Membership mirror.** Could the org accept an owner-signed list of allowed principals (or the circle's member list mapped to principals) and refuse everyone else, so access follows the circle without per-member calls? What identity would the operator verify the owner by?
- **Q-P9. Reads.** Which routes agents should query (`/v1/notes` with `q`, `/v1/search`, `/v1/search/semantic`), and which scopes each needs. Today some read routes are outside every PAT scope.
- **Q-P10. Attribution.** Is a note's author recorded from the token's principal (unforgeable), or only from the client-supplied `actor`? Can one member supersede or retract another's note?
- **Q-P11. Code graph.** Does the shared org hold a mapped code graph of the circle's repositories, and who maps it, given ingestion is refused under a PAT? Piece 4's node links depend on it.
- **Q-P12. Retention and deletion.** Session TTLs, deleting one member's records when they leave, export, and what the operator's access and encryption-at-rest policy is, in words we can put in the docs.
- **Q-P13. Stability.** A versioned, stable contract for the note and session routes across the OSS backend and the hosted one; a stable public endpoint per graph (no redirects); rate limits and the error shape for quota.

### 13.3 Technical

- **Q-T1.** A project shared with two bound circles: stay local (today), or let the person pick one graph per project (`p2p project graph <circle>`), which would be a person-only widening choice?
- **Q-T2.** Credential storage in the OS keychain instead of a sealed file in `P2P_HOME` (the history key has the same gap).
- **Q-T3.** Whether `x:ix.graph-enrolled` should also go to admins, so revocation can happen while the owner is offline (it requires admins to hold an admin credential at the operator).
- **Q-T4.** Reads from a session whose target is local: refuse (proposed: the query text itself would carry private context to the operator), or allow reads of a named circle's graph from the person's own terminal only?

## 14. Alternatives considered

- **A. A generic owner-signed attribute on circle versions** (chosen: decision D6). Small, Ix-free core change; reuses every circle rule.
- **B. An extension envelope from the owner** (`x:ix.graph-bind`, device-signed, accepted if the sender is the head's owner). No core change, but the binding then needs its own versioning, its own handling of ownership transfer, forks and freezes, and its own delivery to new members. Every one of those has been reviewed for circle versions; re-doing them in an extension is where bugs would hide.
- **C. Per-member local configuration** (each member types the endpoint). No core change, but members can diverge, nothing stops one being talked into another endpoint, and "the circle's graph" has no single definition for the chokepoint to check.
- **D. The owner's identity document.** Per-user, not per-circle; wrong scope.
- **E. Client-side-encrypted shared graph.** Members encrypt records under a circle key; the operator stores ciphertext. It loses server-side search and graph queries, which are the point (§3.2). Worth revisiting for a "sealed notes" class later.
- **F. Running `ix` (Ix Pro) with `IX_PAT`** instead of an in-process client. Rejected in §8.5.

## 15. Threat model additions

New adversaries, added to threat-model.md "Graph targets (Ix)":

| Id | Adversary | What they can do | What stops or limits it |
|---|---|---|---|
| **O** | **The graph's operator** | reads everything written; can serve false or hostile content to reads; sees query text and timing | disclosed (§11); reads are framed as untrusted data to models, never instructions; nothing is written without the owner's binding and the member's enrollment |
| **M** | **A co-member** | writes misleading or prompt-injecting notes that others' agents read | records framed "agent-generated, untrusted"; attribution by principal (Q-P10); the circle can remove them |
| **OW** | **A malicious or compromised circle owner** | rebinds the circle to a graph they control | a new `gid` forces every member to re-enroll and see the new endpoint (§7.3); same `gid` with a new endpoint is refused; owner compromise already lets them read the circle's push traffic, so this adds a durable copy only for members who re-enroll |
| **RM** | **A removed member** | keeps reading (and writing) with their token | the honest client stops at once; the operator's revocation (§8.4) stops any client; the owner's doctor shows unrevoked removals; past data stays read |
| **AG** | **An agent with the person's shell** | tries to make a private project write to the shared graph, or to read the token | the chokepoint (G2) and the person-only commands; the token is never in the environment or argv; sandboxing `P2P_HOME` is the hard barrier, as today |
| **RP** | **A repository or project config** | ships a file naming a graph, or sets `IX_*` variables | the registry is filled only from owner-signed circle state plus the person's enrollment (§7.1); the environment can only turn shared graphs off |
| **NW** | **A network attacker** | redirects or intercepts the endpoint | https only, TLS validated, no redirects followed, the token sent to one origin and path prefix only |

Rules added under "Graph targets (Ix)":

- A `shared` target names exactly one circle, and only a circle in the registry of §7.1.
- A credential is used only with the endpoint and `gid` it was enrolled for, and only for a target whose `cid` and `gid` match; ext-ix checks the target again, and the operator checks the token's org (three independent checks).
- Graph memory writes to a shared graph only for the `(cid, gid)` it gathered under, re-checked at drain.

## 16. Test plan

Unit tests next to the code they cover, plus a cross-version case in the compatibility matrix. Adversarial cases first:

**The boundary (projects.ts, graph-memory.ts):**

1. A private project, an unmapped one, a `.p2p-private` one, and a session that touched any of them, with circle A bound and enrolled: target `local`; graph memory writes nothing to A; reads of A refused.
2. A project shared with A only, A and B both bound and enrolled: target is A's graph, with A's endpoint and A's token, never B's. The same project with a path argument inside a project shared with B only: `local`.
3. A project shared with A and B, both bound: `local`, with that reason.
4. A session whose target is A at gather time and becomes private before drain: the batch is dropped (`not_shared`), and the writer is never called with A's token.
5. A rebinding of A (new `gid`) between gather and drain: dropped (`target_changed`), not written to the new binding.
6. A circle version with the same `gid` and a different endpoint: no registry entry; an alert.
7. A version without `ix.graph`, signed by an **admin** or a **former owner** (rejected by the chain), or delivered by a non-member: no registry entry.
8. An `ix.graph` attribute arriving in a peer's extension envelope, an environment variable, config.json, or a file in the repository: no registry entry.
9. The person removed from A (a head without them), or after `leave`: target local at once; the token deleted; self-revocation attempted.
10. An unregistered session (no front-end token) in a project shared with bound A: `local`.
11. A frozen circle: `local`.

**Credentials (ext-ix, enrollment):**

12. A token whose introspection names another graph, broader scopes, or an expired date: refused at enrollment, nothing saved.
13. The token never appears in any child process's environment or argv, in `p2p doctor --json`, in logs or in errors (grep the outputs of the whole suite for a canary token).
14. A 3xx from the endpoint: not followed; the canary token never reaches the redirect target (a second test server records any request).
15. A 401: marked revoked; no further requests.
16. An older ext-ix (`graphTargets: 1`): never handed a shared target or a token.
17. `P2P_IX_SHARED_GRAPH=1` in the environment with shared graphs off in config.json: still off.

**Removal (owner side):**

18. The owner publishes a removal of a bound circle's member: the owner's client calls the revocation route for that member's principal (a fake operator records it), or, without an admin credential, `p2p doctor` reports the unrevoked member until it is done.

**Compatibility:**

19. A 3.1 client before this RFC receives a circle version with `x`: ignored, the circle still accepted, all targets local.
20. A pre-3.1 client: the owner's client doesn't publish `x` while that member's device lacks `circlex.v1` (without `--force-old-members`).
21. Malformed `x` (unregistered namespace, oversized value, 9 entries): the version is `malformed` on new clients.

**Failure modes:** each row of §12 against a fake operator (timeouts, 5xx, 403 per route, TLS failure), checking counts in `p2p doctor` and that the local write still happens.

## 17. Implementation plan (one PR per phase)

| Phase | PR | Contents | Depends on |
|---|---|---|---|
| **G0** | this RFC | `docs/rfcs/0003-shared-team-graph.md`; a pointer in protocol.md's roadmap. §13.1 decided 2026-11-12 | — |
| **G1** | the Ix Pro contract | answers to §13.2, recorded in this RFC; routes and scopes available on a staging operator | G0 accepted |
| **G2** | core: accept `x` | §5.2 shape checks, the namespace registry, `circlex.v1` cap advertised; protocol.md amendment and review-log entry; never emitted | G0 accepted |
| **G3** | p2p: registry and enrollment (read-only) | `circle graph set/unset` (behind a flag, not emitting until G7), `ix graph join/leave/show`, the sealed enrollment store, §7.1 registry, `graphTargets: 2` contract, doctor and `project show` lines; tests 1-11, 16-17 | G1, G2 |
| **G4** | ext-ix: shared writer | the in-process HTTP client (§8.5), the per-circle queue and drain rules (§10.3), `x:ix.graph-enrolled`; tests 12-15, §12 | G3 |
| **G5** | reads for agents | `p2p ix graph search/notes/show`, the mod's and the Codex bridge's tools, untrusted framing | G4 |
| **G6** | owner-side revocation | §8.4 with the operator's admin routes; test 18 | G4, Q-P7 |
| **G7** | emit `x` | the owner's client may publish bindings (§9.2 step 2); tests 19-21 in the cross-version matrix | G2 two releases old |

## 18. References

- [protocol.md](../protocol.md) §3.3 (circles) and §8 (extensions); [compatibility.md](../compatibility.md) (protocol 3.1, `crit`, two-step rollout).
- [concepts.md](../concepts.md), "Projects", "Graph targets", "Graph memory"; [threat-model.md](../security/threat-model.md), "Graph targets (Ix)".
- `packages/p2p/src/projects.ts` (`graphTarget`, `graphTargetOf`, `SHARED_GRAPHS`, `normalizeSharedEndpoint`), `packages/p2p/src/graph-memory.ts` (`drainBatch`), `packages/p2p/src/extensions.ts` (`ExtGraphTarget`, `ExtContext.graphTarget`), `packages/ext-ix/src/ix.ts` (`checkedTarget`, `ixEnv`, `refuseForTarget`), `packages/ext-ix/src/memory.ts`.
- The Ix repository: `docs/api/README.md` and `docs/api/openapi.yaml` ("Notes & Sessions"); `ix-cli/src/cli/register/oss-fallbacks.ts` (OSS `note` and `session` only when Ix Pro didn't load).
- RFC 8628 (OAuth 2.0 Device Authorization Grant); RFC 7662 (OAuth 2.0 Token Introspection); RFC 7009 (OAuth 2.0 Token Revocation).
- [RFC 0001](0001-metadata-privacy-and-tor.md) (format and rollout pattern).
