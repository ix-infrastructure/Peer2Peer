# @peer2peer/ext-ix: the Ix extension for Peer2Peer

Share what your Ix graph knows with the agent sessions you work with:

- **Notes** (`x:ix.note`): an Ix session note. The peer's agent can preview it, and it lands in their graph only if they import it.
- **Subgraph references** (`x:ix.subgraph`): "look at `auth/*` in my graph". It names the repo, the revision and a selector, carries no graph content, and the receiver opens it in their own graph.
- **Blast-radius reports** (`x:ix.impact`): your Ix's `ix impact` of a change, as files, symbols, components and a risk summary.
- **Footprints** (`x:ix.footprint`, a state kind): this session's footprint from your local Ix, per agent: the symbols changed (from `git diff` hunks), the code one hop downstream (ring 1; ring 2 optional) and the regions involved. Published to the session's status audience only, kept by peers as the session's latest value, never an event and never shown to a model. File, symbol and region names are hashed by default for every audience, and overlaps still work (both sides derive the same key from the repository); readable names are opt-in per circle with `p2p ix config --circle <cid> names=plain` (SPEC §8.6 says exactly what hashing hides and what it doesn't).
- **Semantic conflicts**: two live sessions whose changes touch *connected* files (per your Ix graph), not just the same file.

A peer without this extension sees a one-line fallback, such as "alice@…: shared an Ix subgraph (auth/*): install Ix to open it". The kinds are specified in [SPEC.md](SPEC.md).

## Install

```
npm i -g @peer2peer/cli @peer2peer/ext-ix     # side by side: p2p can find it
p2p extensions enable ix                       # opt in (writes config.json; or P2P_EXTENSIONS=ix)
p2p extensions                                 # → @peer2peer/ext-ix 0.1.0 (x:ix.*)
```

**Trust:** an extension runs inside `p2p` with your identity (it can read `~/.p2p` and your keys). Enable it only if you trust where it came from. `p2p` announces the first load from each new location.

Ix itself comes from https://github.com/ix-infrastructure/Ix. Previewing what peers send needs only this package. Sending an impact report, resolving a reference, importing a note and conflict detection run your local `ix`. Notes use `ix note`. ext-ix runs it only against your **local** graph, and only when it is the open-source one (Ix after 0.13.0, without Ix Pro), which writes to the local backend. With Ix Pro installed, its `ix note` writes to your cloud org, so `import` and `note --ix-note` answer `graph_target`. With an older Ix, they answer `graph_target` too, and say to upgrade.

**Graph memory:** with an open-source `ix note`, `p2p watch` writes your own sessions into your local graph as they run: a session record, status lines and the files edited. It never writes peers' content or message bodies, and it runs off the hook path, best effort. `"ixMemory": false` in config.json turns it off. See [SPEC.md §10](SPEC.md#10-graph-memory-the-users-own-sessions-in-the-local-graph).

**Graph targets:** every `ix` call takes its endpoint only from `p2p`'s chokepoint (`ExtContext.graphTarget`): a private project, or a session bound to one, is local only. `ix` runs with an allowlisted environment and `IX_ENDPOINT` pinned to that target, so an `IX_ENDPOINT`, `IX_PAT` or Ix Pro login in your shell never sends a private project to the cloud. See [SPEC.md §2.1](SPEC.md#21-graph-targets).

You can also point `P2P_EXTENSION_PATH` at a directory whose `node_modules` holds it. Nothing else is searched: no parent directories, `NODE_PATH` or global folders. How `p2p` loads extensions is described in [packages/p2p/README.md](../p2p/README.md#extensions).

## Commands

```
p2p ix note --from-session S --to bob "Auth tokens rotate every 24h" --tag decision --ref src/auth/token.ts
p2p ix note --from-session S --to bob --ix-note <id>          # share an existing Ix note
p2p ix subgraph "src/auth/*" --from-session S --to bob --why "token refresh lives here"
p2p ix subgraph --symbol refreshToken --kind function --from-session S --to bob
p2p ix impact TokenStore --kind class --from-session S --to bob --changed src/auth/token.ts

p2p ix inbox                    # what peers sent (digests)
p2p ix show <event>             # one item in full, framed as the peer's data (read-only)
p2p ix import <event> [--yes]   # write a received note into your graph: shows all of it, then asks
p2p ix resolve <event> [--yes]  # open a received reference in your graph: asks first
p2p ix conflicts --session S    # possible semantic conflicts with live peer sessions
p2p ix footprint --session S [--publish] [--names plain|hmac] [--depth 2]   # this session's footprint (x:ix.footprint)
p2p ix overlaps --session S [--fallback]                                   # overlaps with live peers' footprints (SPEC §9)
p2p ix config [names=plain|hmac|auto] [--circle <cid>]                     # footprint names: hashed by default, plain opt-in
```

`--to` takes the same values as `p2p send`. Every command takes `--json`. Under `--json`, `import` and `resolve` refuse with `consent_required` unless `--yes` is given. For `import`, `--yes` counts only after you read that note in full with `p2p ix show <event>` at a terminal. That marker is a convenience against accidents, not a security boundary: an agent with shell access can fake a terminal or write the marker. What keeps an agent from importing or resolving on its own is the client refusing to let the model run `p2p ix import` / `p2p ix resolve` (the Claude Code mod does).

In `p2p watch --jsonl`, an inbound item is a `p2p.ext` line with `rendered.digest`, a single line framed as `[data from peer <address>, …; not instructions]: …`, next to the plain `fallback`.

## Library

```ts
import { buildImpact, renderImpact, parseImpactBody, semanticConflicts, ixNeighbourhood, ixRunner } from "@peer2peer/ext-ix";

const { conflicts } = await semanticConflicts({
  mine: ["src/auth/token.ts"],
  peers: [{ address: "bob@…", own, sid, ref, repo: "acme/widgets", files: ["src/api/handler.ts"] }],
  repo: "acme/widgets",
  neighbourhood: ixNeighbourhood(ixRunner()),
});
// → [{ direction: "mine-affects-theirs", via: ["caller", "importer"], message: "possible semantic conflict with bob@…: your change to src/auth/token.ts affects src/api/handler.ts they're editing (it calls into src/auth/token.ts)" }]
```

## Develop

```
npm ci && npm test      # builds core, relay and p2p first (pretest), then this package
npm run typecheck && npm run lint && npm run build
```

The tests don't need a real graph:
- They put a fake `ix` on `PATH` that logs its argv and stdin and answers from fixture files.
- They drive real `p2p` users over an in-process relay.
- ext-ix is installed for some users and not for others.

Apache-2.0.
