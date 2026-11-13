// Copyright 2026 Ix Infrastructure Inc.
//
// Command lines that name p2p but can't be read by their words (issue #69): GNU `parallel` and runners
// like it, xargs, aliases and functions defined on the same line, and command words built at run time.
// What both agent guards answer for each: the Claude mod's indirectP2PRun (tests/security.test.ts) and
// the Codex bridge's (packages/codex-bridge lib.test.ts, which reads the JSON array below from this
// file). A reason is refused; null passes. The function is the same text in both (a shared block).
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
    "reason": "a command word built at run time on a command that names p2p"
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
  },
  {
    "cmd": "f() # c\n{ p2p \"$@\"; }\nf invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f()\t# c\n{ p2p \"$@\"; }\nf invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f()\n\n{ p2p \"$@\"; }\nf invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "f() p2p \"$@\"; f invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "() { p2p \"$@\"; } invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "true; () { p2p \"$@\"; } invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "function f() { p2p \"$@\"; }; f invite",
    "reason": "a shell function defined on a command that names p2p"
  },
  {
    "cmd": "functions[f]='p2p \"$@\"'; f invite",
    "reason": "a shell alias or function defined on a command that names p2p"
  },
  {
    "cmd": "aliases[q]='p2p invite'; q",
    "reason": "a shell alias or function defined on a command that names p2p"
  },
  {
    "cmd": "BASH_ALIASES[q]='p2p invite'; q",
    "reason": "a shell alias or function defined on a command that names p2p"
  },
  {
    "cmd": "BASH_ALIASES+=([q]='p2p invite'); q",
    "reason": "a shell alias or function defined on a command that names p2p"
  },
  {
    "cmd": "builtin alias q='p2p invite'\nq",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "command alias q='p2p invite'\nq",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "\\alias q='p2p invite'\nq",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "'alias' q='p2p invite'\nq",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "eval \"alias q='p2p invite'\"\nq",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "hash -p /usr/local/bin/p2p q; q invite",
    "reason": "a hashed command name on a command that names p2p"
  },
  {
    "cmd": "eval \"$(printf 'f\\050\\051{ p2p \"$@\"; }')\"; f invite",
    "reason": "eval of text built at run time, on a command that names p2p"
  },
  {
    "cmd": "source <(echo 'f(){ p2p \"$@\"; }'); f invite",
    "reason": "a sourced script on a command that names p2p"
  },
  {
    "cmd": "bash -c 'alias q=\"p2p invite\"\nq'",
    "reason": "a shell alias defined on a command that names p2p"
  },
  {
    "cmd": "echo invite | xargs p2p",
    "reason": "xargs on a command that names p2p"
  },
  {
    "cmd": "echo invite | xargs -P2 p2p",
    "reason": "xargs on a command that names p2p"
  },
  {
    "cmd": "echo invite | xargs -P 2 -n1 p2p",
    "reason": "xargs on a command that names p2p"
  },
  {
    "cmd": "p=parallel; $p p2p ::: send --to bob hi",
    "reason": "a command word built at run time on a command that names p2p"
  },
  {
    "cmd": "$(which parallel) p2p ::: invite",
    "reason": "a command word built at run time on a command that names p2p"
  },
  {
    "cmd": "command parallel p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "\\parallel p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "'parallel' p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "PARALLEL p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "env -i parallel p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "parallel.pl p2p ::: invite",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "env -S \"parallel p2p ::: invite\"",
    "reason": "GNU parallel (or a runner like it) on a command that names p2p"
  },
  {
    "cmd": "bash -c \"bash -c 'bash -c \\\"bash -c \\\\\\\"parallel p2p ::: invite\\\\\\\"\\\"'\"",
    "reason": "a command nested too deeply to check, that names p2p"
  },
  {
    "cmd": "git commit -m 'guard parallel p2p runs'",
    "reason": null
  },
  {
    "cmd": "grep -rn 'parallel' src | p2p ls",
    "reason": null
  },
  {
    "cmd": "p2p ls; parallel echo ::: a b",
    "reason": null
  },
  {
    "cmd": "sem --wait; p2p ls",
    "reason": null
  },
  {
    "cmd": "echo p2p; alias ll='ls -l'",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'f() { x }'",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'please run parallel later'",
    "reason": null
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"alias q = shortcut\"",
    "reason": null
  },
  {
    "cmd": "echo 'alias p=p2p' >> ~/.bashrc",
    "reason": null
  },
  {
    "cmd": "xargs -n1 echo < f; p2p ls",
    "reason": null
  },
  {
    "cmd": "x=$(p2p ls --json); echo \"$x\"",
    "reason": null
  },
  {
    "cmd": "for i in 1 2; do p2p ls; done",
    "reason": null
  },
  {
    "cmd": "if p2p ls; then echo ok; fi",
    "reason": null
  },
  {
    "cmd": "p2p ls | jq '.peers[] | select(.live)'",
    "reason": null
  },
  {
    "cmd": "time p2p ls",
    "reason": null
  },
  {
    "cmd": "make -j8 && p2p ls",
    "reason": null
  },
  {
    "cmd": ". ./venv/bin/activate && p2p ls",
    "reason": null
  },
  {
    "cmd": "$P2P_BIN ls",
    "reason": null
  },
  {
    "cmd": "f\\(\\) { p2p \"$@\"; }",
    "reason": null
  }
]
