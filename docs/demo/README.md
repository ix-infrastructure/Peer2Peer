# Demo

A reproducible two-user demo of Peer2Peer: setup, a circle, an invite and a join, each seeing the other's agent session, a message, and a conflict flag.

Everything runs **on your machine**. [`demo-env.sh`](demo-env.sh) starts a throwaway relay on `127.0.0.1` with an in-memory database, and gives two users, `ann` and `ben`, their own temporary `P2P_HOME`s. The relay's canonical URL (`wss://relay.demo.test/v3`) resolves nowhere: `P2P_RELAY_TRANSPORT` maps it to the local listener. There's no network, no account and no credentials, and everything is deleted when the shell exits.

## Run it (about 30 seconds)

From the repository root:

```sh
(cd packages/core && npm ci && npm run build)
(cd packages/relay && npm ci && npm run build)
(cd packages/codex-bridge && npm ci && npm run build)   # for the conflict step
docs/demo/two-friends.sh
```

It uses the committed single-file CLI (`mods/claude/peer2peer/bin/p2p.mjs`). The conflict step prints the same `<peer-activity>` digest, with its `POTENTIAL CONFLICT` line, that the Codex bridge puts in front of its model (`p2p_peer_activity`). It's built from the real `p2p ls --json` output and the bridge's own `peerActivity()`. The Claude Code mod applies the same same-file rule.

To poke around yourself: `source docs/demo/demo-env.sh`, then use `ann …` and `ben …` like `p2p …` (and `demo_inbox`, `demo_conflicts`). Set `DEMO_KEEP=1` to keep the temp directory.

## Render the GIF

The README's hero slot expects `docs/demo/two-friends.gif`, rendered with [charmbracelet/vhs](https://github.com/charmbracelet/vhs) from [`two-friends.tape`](two-friends.tape):

```sh
brew install vhs            # or: go install github.com/charmbracelet/vhs@latest (needs ttyd and ffmpeg)
vhs docs/demo/two-friends.tape
```

The README already shows it. Fingerprints are random on every run, so re-render whenever the CLI output changes, and keep the GIF under 3 MB (lower `Width` or raise `TypingSpeed` if needed). The tape waits for the `$ ` prompt after every command, so a slow step never garbles the next one. Before committing, look at the frames (for example `ffmpeg -i docs/demo/two-friends.gif -vf fps=1/3 /tmp/f%03d.png`): only `ann`, `ben`, the throwaway relay name and random fingerprints may appear, never a real name, path or host.

A Claude Code recording (the `ListAgents` *Peer2Peer* section, a `<cross-session-message>`, the held-item buttons) needs real Claude sessions and accounts, so it isn't scripted here. If you record one, use throwaway identities and a local relay, and check every frame for codes, phrases and private repo names before publishing.
