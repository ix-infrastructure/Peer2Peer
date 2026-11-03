# Extensions

Extensions add optional features to Peer2Peer without changing the core network. The rules are in the [protocol](protocol.md) §8 and [architecture.md](architecture.md#the-rules-that-keep-the-layers-apart):

- **Two seams only:** extension envelope kinds (`x:<ns>.<type>`), each with a required plain-text **fallback**, and **trust providers**, which add namespaced badges (`✓ <ns>: …`).
- **Information, never authorisation.** Who may message whom is decided only by keys, friendships, circles and rosters, on your own device.
- **Core never imports an extension.** `scripts/check-boundaries.mjs` enforces that for the code.
- **Namespaces are registered** in protocol §8.3 by PR. See [GOVERNANCE.md](../GOVERNANCE.md#extension-namespaces).

## Trust: an extension is code you run with your identity

When `p2p` loads `@peer2peer/ext-<ns>`, that code runs **inside the `p2p` process**, with access to `~/.p2p` and your keys. `ExtContext` is the API an extension is meant to use, but **it isn't a sandbox**. So loading is:

- **opt-in:** `p2p extensions enable <ns>` (or `P2P_EXTENSIONS=<ns>` in your own shell). Nothing is enabled by default;
- **limited to registered namespaces** (`ix`, `kartr`);
- **limited to explicit directories:** `P2P_EXTENSION_PATH` entries and the CLI's own sibling `node_modules`. There's no walk-up, no `NODE_PATH` and no globals, and never the repository your agent is working in;
- **announced** the first time it loads from a new location;
- **degrading:** a missing or broken extension is a warning, and its kinds show their fallback.

In the Claude Code mod and the Codex bridge, the model can't enable extensions. Details: [packages/p2p/README.md § Extensions](../packages/p2p/README.md#extensions).

## Available: Ix (`x:ix.*`, open source)

[`@peer2peer/ext-ix`](../packages/ext-ix/README.md), specified in [SPEC.md](../packages/ext-ix/SPEC.md):

- **Notes** (`x:ix.note`): share an Ix session note. It lands in the peer's graph only if they import it.
- **Subgraph references** (`x:ix.subgraph`): "look at `auth/*` in my graph". Graph content isn't included; the receiver opens it in their own graph.
- **Blast-radius reports** (`x:ix.impact`): your `ix impact` of a change.
- **Footprints** (`x:ix.footprint`, a state kind): what each session and its subagents are changing as your Ix sees it (changed symbols, one hop downstream, regions), kept by peers as the session's latest value and never shown to a model. File, symbol and region names are hashed by default for every audience; readable names are opt-in per circle (`p2p ix config --circle <cid> names=plain`).
- **Semantic conflicts:** flag peers changing files *connected* to yours in your Ix graph (`P2P_IX_SEMANTIC_CONFLICTS=1` in the Claude Code mod).

Previewing what peers send needs only the extension. Sending impact reports, resolving references, importing notes and conflict detection need [Ix](https://github.com/ix-infrastructure/Ix) installed. Notes use `ix note` from Ix Pro. The Claude Code mod bundles the extension, but it stays off until you enable it.

## Planned: Kartr (`kartr`, paid, for organisations)

Not in this repository yet. Planned: a `kartr.attest` trust provider (a verified "this key is this person at this org" badge), managed circles that follow SSO, and a hosted relay. See the [roadmap](roadmap.md#organisations-kartr-paid-optional).

## Writing an extension

The contract (`P2PExtension`, exported from `@peer2peer/cli`) is `api: 1`, `ns`, `receive()` to validate and render inbound kinds (never acting on them), and declarative `commands` that `p2p` wires up with `--json`. See [packages/p2p/README.md § Extensions](../packages/p2p/README.md#extensions) and use `packages/ext-ix` as the worked example. To get a namespace, open a [Protocol RFC](https://github.com/ix-infrastructure/Peer2Peer/issues/new?template=protocol_rfc.yml).
