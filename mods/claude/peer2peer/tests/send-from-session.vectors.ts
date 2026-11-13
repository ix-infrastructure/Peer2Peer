// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p send` command lines and what both agent guards answer for each: the Claude mod's
// mutatingP2PVerb (tests/security.test.ts) and the Codex bridge's (packages/codex-bridge lib.test.ts,
// which reads the JSON array below from this file). "send (no --from-session)" is refused; null passes.
// Keep the array plain JSON.

export const SEND_VECTORS: { cmd: string; verb: string | null }[] = [
  {
    "cmd": "p2p send --to bob -- --from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob -- --from-session s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p -- send --from-session=s1 --to bob hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --project-dir --from-session s1 --to bob",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to --no-input --from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p --no-input send --to bob -- --from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send hi --from-session=s1 --to bob",
    "verb": null
  },
  {
    "cmd": "p2p send --no-input --to bob --from-session s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --from-session -- --to bob hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to=bob --from-session=s1 -- --to",
    "verb": null
  },
  {
    "cmd": "p2p send --from-session s1 --to \"bob [a1b2c3]\" --stdin",
    "verb": null
  },
  {
    "cmd": "p2p send --to \"bob [a1b2c3]\" --from-session s1 --stdin",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob 2>/dev/null --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 hi 2>&1",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob --from-session=$SID hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --from-session s1 --to bob hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob\\ --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to 'bob --from-session=s1' hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to \"bob\"\\ --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --no-input --from-session=s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to --no-input --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --project-dir --from-session=s1 --to bob hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --project-dirs-over --from-session=s1 --to bob hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to=bob --from-session=s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob hi --from-session s1",
    "verb": null
  },
  {
    "cmd": "p2p --no-input send --to bob --from-session s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob $'--from-session=s1'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to $'bob\\x20--from-session=s1' hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to $'bob\\n--from-session=s1' hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob${IFS}--from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 -- -- x",
    "verb": null
  },
  {
    "cmd": "p2p send --stdin --to bob <<< --from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=\"\" hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob #--from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob '#' --from-session=s1",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to \"$(echo bob)\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \"--from-session\"=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 hi; p2p send --to bob hi2",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 hi | p2p send --to bob",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 `p2p send --to bob x`",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 \"$(p2p send --to bob x)\"",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1\np2p send --to bob x",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --notify-when-idle --from-session=s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 --to --from-session=x",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob --project-dir= --from-session=s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --to bob --to\t--from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to\\\n--from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to '' --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to \"\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to $EMPTY --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --t\\o --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --'to' --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \"--to\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --project-d\"ir\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \"-\"-to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob {--to,} --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --from-session=s1 --to {--from-session=s1,x}",
    "verb": null
  },
  {
    "cmd": "node p2p.mjs send --to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "npx @peer2peer/cli send --to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "npx -y @peer2peer/cli send --to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob $'--to' --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob ${X:---to} --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \"${X:---to}\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob $(echo --to) --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob `echo --to` --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --t? --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --[t]o --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --t* --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob $T --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "T=--to; p2p send --to bob $T --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob ~--to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \"\"--to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob ''--to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to\"\" --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --pro{ject-dir,} --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to $'\\x2d-from-session=s1' hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to $'--from-session=s1' hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob --to {--from-session=s1,} hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \\--to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob -\\-to --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob @(--to) --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "a=(--to); p2p send --to bob ${a[@]} --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob $@ --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob $* --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob ${!x} --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob\r--from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send \r--from-session=s1 --to bob hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "p2p send --to bob \r --from-session=s1 hi",
    "verb": null
  },
  {
    "cmd": "p2p send --from-session=s1 --to bob hi\r",
    "verb": null
  },
  {
    "cmd": "env -S 'p2p send --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -S 'p2p send --from-session=s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -S'p2p send --from-session=s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -vS 'p2p send --from-session=s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -i -S 'p2p send --from-session s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -u HOME -S 'p2p send --from-session s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env --split-string='p2p send --from-session=s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env --split-string 'p2p send --from-session s1 --to bob hi'",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env -S 'p2p send --to bob' --from-session=s1 hi",
    "verb": "send (no --from-session)"
  },
  {
    "cmd": "env p2p send --from-session s1 --to bob hi",
    "verb": null
  },
  {
    "cmd": "env A=1 p2p send --from-session=s1 --to bob hi",
    "verb": null
  }
]
