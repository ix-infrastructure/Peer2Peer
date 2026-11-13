// Copyright 2026 Ix Infrastructure Inc.
//
// Command lines that name p2p but can't be read by their words (issue #69): GNU `parallel` and runners
// like it, and aliases or functions defined on the same line. What both agent guards answer for each:
// the Claude mod's indirectP2PRun (tests/security.test.ts) and the Codex bridge's (packages/codex-bridge
// lib.test.ts, which reads the JSON array below from this file). A reason is refused; null passes.
// Keep the array plain JSON.

export const INDIRECT_VECTORS: { cmd: string; reason: string | null }[] = [
  {
    "cmd": "parallel p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "parallel -j1 'p2p {}' ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "parallel p2p send {1} {2} --to bob ::: --to ::: --from-session=s1",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "nice -n 5 parallel p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "echo invite | parallel p2p",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "/usr/bin/parallel --will-cite p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "sem -j2 p2p invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "bash -c 'parallel p2p ::: invite'",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"$(parallel p2p ::: invite)\"",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "alias q='p2p send --to'; q --from-session=s1 bob",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "alias q=p2p; q invite",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "shopt -s expand_aliases\nalias q=p2p\nq invite",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "X=1 alias q=p2p",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "{ alias q=p2p; }",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "bash -c \"alias q=p2p; q invite\"",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "eval 'alias q=p2p'; q invite",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "f(){ p2p \"$@\"; }; f invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f () { p2p \"$@\"; }; f invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f() ( p2p invite ); f",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "function f { p2p \"$@\"; }; f invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "bash -c 'f(){ p2p invite; }; f'",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f()\n{\n  p2p invite\n}\nf",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"runs in parallel\"",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob parallel",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"alias: see the notes\"",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"the function returns early\"",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"fixed the parse() bug\"",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"$(date) function\"",
    "reason": null
  },
  {
    "cmd": "a=(); p2p ls",
    "reason": null
  },
  {
    "cmd": "diff <(p2p ls) <(p2p ls)",
    "reason": null
  },
  {
    "cmd": "p2p ls; echo $(date)",
    "reason": null
  },
  {
    "cmd": "p2p ls",
    "reason": null
  }
]
