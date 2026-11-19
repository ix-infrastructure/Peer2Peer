// Copyright 2026 Ix Infrastructure Inc.
//
// The p2p verbs an agent may never run, and one command line per verb and shape with the verb each
// guard names for it (null: allowed). The Claude mod's Bash guard (hooks/lib.ts MUTATING_ONE, _TWO,
// _FIRST and mutatingP2PVerb; tests/security.test.ts) and the Codex bridge's PreToolUse guard
// (packages/codex-bridge lib.ts, lib.test.ts, which reads the JSON object below from this file) must
// both hold exactly these lists and give these answers: a verb added to one guard and not the other
// fails both suites. Keep the object plain JSON.

export const GUARD_VERBS: { one: string[]; two: string[]; first: string[]; vectors: { cmd: string; verb: string | null }[] } = {
  "one": [
    "join",
    "accept",
    "invite",
    "backup",
    "setup",
    "init",
    "remove",
    "unfriend",
    "block",
    "unblock",
    "petname",
    "link",
    "release",
    "tui",
    "history"
  ],
  "two": [
    "trust add",
    "trust remove",
    "ix import",
    "ix resolve",
    "extensions enable",
    "extensions disable",
    "held approve",
    "held decline",
    "relays add",
    "relays remove",
    "circle invite",
    "circle join",
    "circle create",
    "circle leave",
    "circle propose",
    "circle transfer",
    "circle policy",
    "circle default",
    "circle hold",
    "devices revoke",
    "session roster",
    "identity republish",
    "identity rotate",
    "identity follow",
    "identity dispute",
    "profile set",
    "proof add",
    "invites revoke",
    "codex install",
    "codex release",
    "codex decline",
    "ix note",
    "ix subgraph",
    "ix impact",
    "ix config",
    "project share",
    "project private"
  ],
  "first": [
    "status",
    "receipt",
    "own-agents"
  ],
  "vectors": [
    {
      "cmd": "p2p join",
      "verb": "join"
    },
    {
      "cmd": "p2p --json join arg1",
      "verb": "join"
    },
    {
      "cmd": "p2p join arg1 --json --yes",
      "verb": "join"
    },
    {
      "cmd": "bash -c 'p2p join arg1'",
      "verb": "join"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p join --yes\"",
      "verb": "join"
    },
    {
      "cmd": "nohup p2p join arg1",
      "verb": "join"
    },
    {
      "cmd": "nice -n 5 p2p join",
      "verb": "join"
    },
    {
      "cmd": "timeout 30 p2p join --json",
      "verb": "join"
    },
    {
      "cmd": "true && p2p join",
      "verb": "join"
    },
    {
      "cmd": "npx -y @peer2peer/cli join",
      "verb": "join"
    },
    {
      "cmd": "env -S 'p2p join arg1'",
      "verb": "join"
    },
    {
      "cmd": "eval 'p2p join'",
      "verb": "join"
    },
    {
      "cmd": "p2p accept",
      "verb": "accept"
    },
    {
      "cmd": "p2p --json accept arg1",
      "verb": "accept"
    },
    {
      "cmd": "p2p accept arg1 --json --yes",
      "verb": "accept"
    },
    {
      "cmd": "bash -c 'p2p accept arg1'",
      "verb": "accept"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p accept --yes\"",
      "verb": "accept"
    },
    {
      "cmd": "nohup p2p accept arg1",
      "verb": "accept"
    },
    {
      "cmd": "nice -n 5 p2p accept",
      "verb": "accept"
    },
    {
      "cmd": "timeout 30 p2p accept --json",
      "verb": "accept"
    },
    {
      "cmd": "true && p2p accept",
      "verb": "accept"
    },
    {
      "cmd": "npx -y @peer2peer/cli accept",
      "verb": "accept"
    },
    {
      "cmd": "env -S 'p2p accept arg1'",
      "verb": "accept"
    },
    {
      "cmd": "eval 'p2p accept'",
      "verb": "accept"
    },
    {
      "cmd": "p2p invite",
      "verb": "invite"
    },
    {
      "cmd": "p2p --json invite arg1",
      "verb": "invite"
    },
    {
      "cmd": "p2p invite arg1 --json --yes",
      "verb": "invite"
    },
    {
      "cmd": "bash -c 'p2p invite arg1'",
      "verb": "invite"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p invite --yes\"",
      "verb": "invite"
    },
    {
      "cmd": "nohup p2p invite arg1",
      "verb": "invite"
    },
    {
      "cmd": "nice -n 5 p2p invite",
      "verb": "invite"
    },
    {
      "cmd": "timeout 30 p2p invite --json",
      "verb": "invite"
    },
    {
      "cmd": "true && p2p invite",
      "verb": "invite"
    },
    {
      "cmd": "npx -y @peer2peer/cli invite",
      "verb": "invite"
    },
    {
      "cmd": "env -S 'p2p invite arg1'",
      "verb": "invite"
    },
    {
      "cmd": "eval 'p2p invite'",
      "verb": "invite"
    },
    {
      "cmd": "p2p backup",
      "verb": "backup"
    },
    {
      "cmd": "p2p --json backup arg1",
      "verb": "backup"
    },
    {
      "cmd": "p2p backup arg1 --json --yes",
      "verb": "backup"
    },
    {
      "cmd": "bash -c 'p2p backup arg1'",
      "verb": "backup"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p backup --yes\"",
      "verb": "backup"
    },
    {
      "cmd": "nohup p2p backup arg1",
      "verb": "backup"
    },
    {
      "cmd": "nice -n 5 p2p backup",
      "verb": "backup"
    },
    {
      "cmd": "timeout 30 p2p backup --json",
      "verb": "backup"
    },
    {
      "cmd": "true && p2p backup",
      "verb": "backup"
    },
    {
      "cmd": "npx -y @peer2peer/cli backup",
      "verb": "backup"
    },
    {
      "cmd": "env -S 'p2p backup arg1'",
      "verb": "backup"
    },
    {
      "cmd": "eval 'p2p backup'",
      "verb": "backup"
    },
    {
      "cmd": "p2p setup",
      "verb": "setup"
    },
    {
      "cmd": "p2p --json setup arg1",
      "verb": "setup"
    },
    {
      "cmd": "p2p setup arg1 --json --yes",
      "verb": "setup"
    },
    {
      "cmd": "bash -c 'p2p setup arg1'",
      "verb": "setup"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p setup --yes\"",
      "verb": "setup"
    },
    {
      "cmd": "nohup p2p setup arg1",
      "verb": "setup"
    },
    {
      "cmd": "nice -n 5 p2p setup",
      "verb": "setup"
    },
    {
      "cmd": "timeout 30 p2p setup --json",
      "verb": "setup"
    },
    {
      "cmd": "true && p2p setup",
      "verb": "setup"
    },
    {
      "cmd": "npx -y @peer2peer/cli setup",
      "verb": "setup"
    },
    {
      "cmd": "env -S 'p2p setup arg1'",
      "verb": "setup"
    },
    {
      "cmd": "eval 'p2p setup'",
      "verb": "setup"
    },
    {
      "cmd": "p2p init",
      "verb": "init"
    },
    {
      "cmd": "p2p --json init arg1",
      "verb": "init"
    },
    {
      "cmd": "p2p init arg1 --json --yes",
      "verb": "init"
    },
    {
      "cmd": "bash -c 'p2p init arg1'",
      "verb": "init"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p init --yes\"",
      "verb": "init"
    },
    {
      "cmd": "nohup p2p init arg1",
      "verb": "init"
    },
    {
      "cmd": "nice -n 5 p2p init",
      "verb": "init"
    },
    {
      "cmd": "timeout 30 p2p init --json",
      "verb": "init"
    },
    {
      "cmd": "true && p2p init",
      "verb": "init"
    },
    {
      "cmd": "npx -y @peer2peer/cli init",
      "verb": "init"
    },
    {
      "cmd": "env -S 'p2p init arg1'",
      "verb": "init"
    },
    {
      "cmd": "eval 'p2p init'",
      "verb": "init"
    },
    {
      "cmd": "p2p remove",
      "verb": "remove"
    },
    {
      "cmd": "p2p --json remove arg1",
      "verb": "remove"
    },
    {
      "cmd": "p2p remove arg1 --json --yes",
      "verb": "remove"
    },
    {
      "cmd": "bash -c 'p2p remove arg1'",
      "verb": "remove"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p remove --yes\"",
      "verb": "remove"
    },
    {
      "cmd": "nohup p2p remove arg1",
      "verb": "remove"
    },
    {
      "cmd": "nice -n 5 p2p remove",
      "verb": "remove"
    },
    {
      "cmd": "timeout 30 p2p remove --json",
      "verb": "remove"
    },
    {
      "cmd": "true && p2p remove",
      "verb": "remove"
    },
    {
      "cmd": "npx -y @peer2peer/cli remove",
      "verb": "remove"
    },
    {
      "cmd": "env -S 'p2p remove arg1'",
      "verb": "remove"
    },
    {
      "cmd": "eval 'p2p remove'",
      "verb": "remove"
    },
    {
      "cmd": "p2p unfriend",
      "verb": "unfriend"
    },
    {
      "cmd": "p2p --json unfriend arg1",
      "verb": "unfriend"
    },
    {
      "cmd": "p2p unfriend arg1 --json --yes",
      "verb": "unfriend"
    },
    {
      "cmd": "bash -c 'p2p unfriend arg1'",
      "verb": "unfriend"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p unfriend --yes\"",
      "verb": "unfriend"
    },
    {
      "cmd": "nohup p2p unfriend arg1",
      "verb": "unfriend"
    },
    {
      "cmd": "nice -n 5 p2p unfriend",
      "verb": "unfriend"
    },
    {
      "cmd": "timeout 30 p2p unfriend --json",
      "verb": "unfriend"
    },
    {
      "cmd": "true && p2p unfriend",
      "verb": "unfriend"
    },
    {
      "cmd": "npx -y @peer2peer/cli unfriend",
      "verb": "unfriend"
    },
    {
      "cmd": "env -S 'p2p unfriend arg1'",
      "verb": "unfriend"
    },
    {
      "cmd": "eval 'p2p unfriend'",
      "verb": "unfriend"
    },
    {
      "cmd": "p2p block",
      "verb": "block"
    },
    {
      "cmd": "p2p --json block arg1",
      "verb": "block"
    },
    {
      "cmd": "p2p block arg1 --json --yes",
      "verb": "block"
    },
    {
      "cmd": "bash -c 'p2p block arg1'",
      "verb": "block"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p block --yes\"",
      "verb": "block"
    },
    {
      "cmd": "nohup p2p block arg1",
      "verb": "block"
    },
    {
      "cmd": "nice -n 5 p2p block",
      "verb": "block"
    },
    {
      "cmd": "timeout 30 p2p block --json",
      "verb": "block"
    },
    {
      "cmd": "true && p2p block",
      "verb": "block"
    },
    {
      "cmd": "npx -y @peer2peer/cli block",
      "verb": "block"
    },
    {
      "cmd": "env -S 'p2p block arg1'",
      "verb": "block"
    },
    {
      "cmd": "eval 'p2p block'",
      "verb": "block"
    },
    {
      "cmd": "p2p unblock",
      "verb": "unblock"
    },
    {
      "cmd": "p2p --json unblock arg1",
      "verb": "unblock"
    },
    {
      "cmd": "p2p unblock arg1 --json --yes",
      "verb": "unblock"
    },
    {
      "cmd": "bash -c 'p2p unblock arg1'",
      "verb": "unblock"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p unblock --yes\"",
      "verb": "unblock"
    },
    {
      "cmd": "nohup p2p unblock arg1",
      "verb": "unblock"
    },
    {
      "cmd": "nice -n 5 p2p unblock",
      "verb": "unblock"
    },
    {
      "cmd": "timeout 30 p2p unblock --json",
      "verb": "unblock"
    },
    {
      "cmd": "true && p2p unblock",
      "verb": "unblock"
    },
    {
      "cmd": "npx -y @peer2peer/cli unblock",
      "verb": "unblock"
    },
    {
      "cmd": "env -S 'p2p unblock arg1'",
      "verb": "unblock"
    },
    {
      "cmd": "eval 'p2p unblock'",
      "verb": "unblock"
    },
    {
      "cmd": "p2p petname",
      "verb": "petname"
    },
    {
      "cmd": "p2p --json petname arg1",
      "verb": "petname"
    },
    {
      "cmd": "p2p petname arg1 --json --yes",
      "verb": "petname"
    },
    {
      "cmd": "bash -c 'p2p petname arg1'",
      "verb": "petname"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p petname --yes\"",
      "verb": "petname"
    },
    {
      "cmd": "nohup p2p petname arg1",
      "verb": "petname"
    },
    {
      "cmd": "nice -n 5 p2p petname",
      "verb": "petname"
    },
    {
      "cmd": "timeout 30 p2p petname --json",
      "verb": "petname"
    },
    {
      "cmd": "true && p2p petname",
      "verb": "petname"
    },
    {
      "cmd": "npx -y @peer2peer/cli petname",
      "verb": "petname"
    },
    {
      "cmd": "env -S 'p2p petname arg1'",
      "verb": "petname"
    },
    {
      "cmd": "eval 'p2p petname'",
      "verb": "petname"
    },
    {
      "cmd": "p2p link",
      "verb": "link"
    },
    {
      "cmd": "p2p --json link arg1",
      "verb": "link"
    },
    {
      "cmd": "p2p link arg1 --json --yes",
      "verb": "link"
    },
    {
      "cmd": "bash -c 'p2p link arg1'",
      "verb": "link"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p link --yes\"",
      "verb": "link"
    },
    {
      "cmd": "nohup p2p link arg1",
      "verb": "link"
    },
    {
      "cmd": "nice -n 5 p2p link",
      "verb": "link"
    },
    {
      "cmd": "timeout 30 p2p link --json",
      "verb": "link"
    },
    {
      "cmd": "true && p2p link",
      "verb": "link"
    },
    {
      "cmd": "npx -y @peer2peer/cli link",
      "verb": "link"
    },
    {
      "cmd": "env -S 'p2p link arg1'",
      "verb": "link"
    },
    {
      "cmd": "eval 'p2p link'",
      "verb": "link"
    },
    {
      "cmd": "p2p release",
      "verb": "release"
    },
    {
      "cmd": "p2p --json release arg1",
      "verb": "release"
    },
    {
      "cmd": "p2p release arg1 --json --yes",
      "verb": "release"
    },
    {
      "cmd": "bash -c 'p2p release arg1'",
      "verb": "release"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p release --yes\"",
      "verb": "release"
    },
    {
      "cmd": "nohup p2p release arg1",
      "verb": "release"
    },
    {
      "cmd": "nice -n 5 p2p release",
      "verb": "release"
    },
    {
      "cmd": "timeout 30 p2p release --json",
      "verb": "release"
    },
    {
      "cmd": "true && p2p release",
      "verb": "release"
    },
    {
      "cmd": "npx -y @peer2peer/cli release",
      "verb": "release"
    },
    {
      "cmd": "env -S 'p2p release arg1'",
      "verb": "release"
    },
    {
      "cmd": "eval 'p2p release'",
      "verb": "release"
    },
    {
      "cmd": "p2p tui",
      "verb": "tui"
    },
    {
      "cmd": "p2p --json tui arg1",
      "verb": "tui"
    },
    {
      "cmd": "p2p tui arg1 --json --yes",
      "verb": "tui"
    },
    {
      "cmd": "bash -c 'p2p tui arg1'",
      "verb": "tui"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p tui --yes\"",
      "verb": "tui"
    },
    {
      "cmd": "nohup p2p tui arg1",
      "verb": "tui"
    },
    {
      "cmd": "nice -n 5 p2p tui",
      "verb": "tui"
    },
    {
      "cmd": "timeout 30 p2p tui --json",
      "verb": "tui"
    },
    {
      "cmd": "true && p2p tui",
      "verb": "tui"
    },
    {
      "cmd": "npx -y @peer2peer/cli tui",
      "verb": "tui"
    },
    {
      "cmd": "env -S 'p2p tui arg1'",
      "verb": "tui"
    },
    {
      "cmd": "eval 'p2p tui'",
      "verb": "tui"
    },
    {
      "cmd": "p2p history",
      "verb": "history"
    },
    {
      "cmd": "p2p --json history arg1",
      "verb": "history"
    },
    {
      "cmd": "p2p history arg1 --json --yes",
      "verb": "history"
    },
    {
      "cmd": "bash -c 'p2p history arg1'",
      "verb": "history"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p history --yes\"",
      "verb": "history"
    },
    {
      "cmd": "nohup p2p history arg1",
      "verb": "history"
    },
    {
      "cmd": "nice -n 5 p2p history",
      "verb": "history"
    },
    {
      "cmd": "timeout 30 p2p history --json",
      "verb": "history"
    },
    {
      "cmd": "true && p2p history",
      "verb": "history"
    },
    {
      "cmd": "npx -y @peer2peer/cli history",
      "verb": "history"
    },
    {
      "cmd": "env -S 'p2p history arg1'",
      "verb": "history"
    },
    {
      "cmd": "eval 'p2p history'",
      "verb": "history"
    },
    {
      "cmd": "p2p trust add",
      "verb": "trust add"
    },
    {
      "cmd": "p2p --json trust --yes add arg1",
      "verb": "trust add"
    },
    {
      "cmd": "p2p trust add arg1 --json --yes",
      "verb": "trust add"
    },
    {
      "cmd": "bash -c 'p2p trust add arg1'",
      "verb": "trust add"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p trust add --yes\"",
      "verb": "trust add"
    },
    {
      "cmd": "nohup p2p trust add arg1",
      "verb": "trust add"
    },
    {
      "cmd": "nice -n 5 p2p trust add",
      "verb": "trust add"
    },
    {
      "cmd": "timeout 30 p2p trust add --json",
      "verb": "trust add"
    },
    {
      "cmd": "true && p2p trust add",
      "verb": "trust add"
    },
    {
      "cmd": "npx -y @peer2peer/cli trust add",
      "verb": "trust add"
    },
    {
      "cmd": "env -S 'p2p trust add arg1'",
      "verb": "trust add"
    },
    {
      "cmd": "eval 'p2p trust add'",
      "verb": "trust add"
    },
    {
      "cmd": "p2p trust remove",
      "verb": "trust remove"
    },
    {
      "cmd": "p2p --json trust --yes remove arg1",
      "verb": "trust remove"
    },
    {
      "cmd": "p2p trust remove arg1 --json --yes",
      "verb": "trust remove"
    },
    {
      "cmd": "bash -c 'p2p trust remove arg1'",
      "verb": "trust remove"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p trust remove --yes\"",
      "verb": "trust remove"
    },
    {
      "cmd": "nohup p2p trust remove arg1",
      "verb": "trust remove"
    },
    {
      "cmd": "nice -n 5 p2p trust remove",
      "verb": "trust remove"
    },
    {
      "cmd": "timeout 30 p2p trust remove --json",
      "verb": "trust remove"
    },
    {
      "cmd": "true && p2p trust remove",
      "verb": "trust remove"
    },
    {
      "cmd": "npx -y @peer2peer/cli trust remove",
      "verb": "trust remove"
    },
    {
      "cmd": "env -S 'p2p trust remove arg1'",
      "verb": "trust remove"
    },
    {
      "cmd": "eval 'p2p trust remove'",
      "verb": "trust remove"
    },
    {
      "cmd": "p2p ix import",
      "verb": "ix import"
    },
    {
      "cmd": "p2p --json ix --yes import arg1",
      "verb": "ix import"
    },
    {
      "cmd": "p2p ix import arg1 --json --yes",
      "verb": "ix import"
    },
    {
      "cmd": "bash -c 'p2p ix import arg1'",
      "verb": "ix import"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix import --yes\"",
      "verb": "ix import"
    },
    {
      "cmd": "nohup p2p ix import arg1",
      "verb": "ix import"
    },
    {
      "cmd": "nice -n 5 p2p ix import",
      "verb": "ix import"
    },
    {
      "cmd": "timeout 30 p2p ix import --json",
      "verb": "ix import"
    },
    {
      "cmd": "true && p2p ix import",
      "verb": "ix import"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix import",
      "verb": "ix import"
    },
    {
      "cmd": "env -S 'p2p ix import arg1'",
      "verb": "ix import"
    },
    {
      "cmd": "eval 'p2p ix import'",
      "verb": "ix import"
    },
    {
      "cmd": "p2p ix resolve",
      "verb": "ix resolve"
    },
    {
      "cmd": "p2p --json ix --yes resolve arg1",
      "verb": "ix resolve"
    },
    {
      "cmd": "p2p ix resolve arg1 --json --yes",
      "verb": "ix resolve"
    },
    {
      "cmd": "bash -c 'p2p ix resolve arg1'",
      "verb": "ix resolve"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix resolve --yes\"",
      "verb": "ix resolve"
    },
    {
      "cmd": "nohup p2p ix resolve arg1",
      "verb": "ix resolve"
    },
    {
      "cmd": "nice -n 5 p2p ix resolve",
      "verb": "ix resolve"
    },
    {
      "cmd": "timeout 30 p2p ix resolve --json",
      "verb": "ix resolve"
    },
    {
      "cmd": "true && p2p ix resolve",
      "verb": "ix resolve"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix resolve",
      "verb": "ix resolve"
    },
    {
      "cmd": "env -S 'p2p ix resolve arg1'",
      "verb": "ix resolve"
    },
    {
      "cmd": "eval 'p2p ix resolve'",
      "verb": "ix resolve"
    },
    {
      "cmd": "p2p extensions enable",
      "verb": "extensions enable"
    },
    {
      "cmd": "p2p --json extensions --yes enable arg1",
      "verb": "extensions enable"
    },
    {
      "cmd": "p2p extensions enable arg1 --json --yes",
      "verb": "extensions enable"
    },
    {
      "cmd": "bash -c 'p2p extensions enable arg1'",
      "verb": "extensions enable"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p extensions enable --yes\"",
      "verb": "extensions enable"
    },
    {
      "cmd": "nohup p2p extensions enable arg1",
      "verb": "extensions enable"
    },
    {
      "cmd": "nice -n 5 p2p extensions enable",
      "verb": "extensions enable"
    },
    {
      "cmd": "timeout 30 p2p extensions enable --json",
      "verb": "extensions enable"
    },
    {
      "cmd": "true && p2p extensions enable",
      "verb": "extensions enable"
    },
    {
      "cmd": "npx -y @peer2peer/cli extensions enable",
      "verb": "extensions enable"
    },
    {
      "cmd": "env -S 'p2p extensions enable arg1'",
      "verb": "extensions enable"
    },
    {
      "cmd": "eval 'p2p extensions enable'",
      "verb": "extensions enable"
    },
    {
      "cmd": "p2p extensions disable",
      "verb": "extensions disable"
    },
    {
      "cmd": "p2p --json extensions --yes disable arg1",
      "verb": "extensions disable"
    },
    {
      "cmd": "p2p extensions disable arg1 --json --yes",
      "verb": "extensions disable"
    },
    {
      "cmd": "bash -c 'p2p extensions disable arg1'",
      "verb": "extensions disable"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p extensions disable --yes\"",
      "verb": "extensions disable"
    },
    {
      "cmd": "nohup p2p extensions disable arg1",
      "verb": "extensions disable"
    },
    {
      "cmd": "nice -n 5 p2p extensions disable",
      "verb": "extensions disable"
    },
    {
      "cmd": "timeout 30 p2p extensions disable --json",
      "verb": "extensions disable"
    },
    {
      "cmd": "true && p2p extensions disable",
      "verb": "extensions disable"
    },
    {
      "cmd": "npx -y @peer2peer/cli extensions disable",
      "verb": "extensions disable"
    },
    {
      "cmd": "env -S 'p2p extensions disable arg1'",
      "verb": "extensions disable"
    },
    {
      "cmd": "eval 'p2p extensions disable'",
      "verb": "extensions disable"
    },
    {
      "cmd": "p2p held approve",
      "verb": "held approve"
    },
    {
      "cmd": "p2p --json held --yes approve arg1",
      "verb": "held approve"
    },
    {
      "cmd": "p2p held approve arg1 --json --yes",
      "verb": "held approve"
    },
    {
      "cmd": "bash -c 'p2p held approve arg1'",
      "verb": "held approve"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p held approve --yes\"",
      "verb": "held approve"
    },
    {
      "cmd": "nohup p2p held approve arg1",
      "verb": "held approve"
    },
    {
      "cmd": "nice -n 5 p2p held approve",
      "verb": "held approve"
    },
    {
      "cmd": "timeout 30 p2p held approve --json",
      "verb": "held approve"
    },
    {
      "cmd": "true && p2p held approve",
      "verb": "held approve"
    },
    {
      "cmd": "npx -y @peer2peer/cli held approve",
      "verb": "held approve"
    },
    {
      "cmd": "env -S 'p2p held approve arg1'",
      "verb": "held approve"
    },
    {
      "cmd": "eval 'p2p held approve'",
      "verb": "held approve"
    },
    {
      "cmd": "p2p held decline",
      "verb": "held decline"
    },
    {
      "cmd": "p2p --json held --yes decline arg1",
      "verb": "held decline"
    },
    {
      "cmd": "p2p held decline arg1 --json --yes",
      "verb": "held decline"
    },
    {
      "cmd": "bash -c 'p2p held decline arg1'",
      "verb": "held decline"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p held decline --yes\"",
      "verb": "held decline"
    },
    {
      "cmd": "nohup p2p held decline arg1",
      "verb": "held decline"
    },
    {
      "cmd": "nice -n 5 p2p held decline",
      "verb": "held decline"
    },
    {
      "cmd": "timeout 30 p2p held decline --json",
      "verb": "held decline"
    },
    {
      "cmd": "true && p2p held decline",
      "verb": "held decline"
    },
    {
      "cmd": "npx -y @peer2peer/cli held decline",
      "verb": "held decline"
    },
    {
      "cmd": "env -S 'p2p held decline arg1'",
      "verb": "held decline"
    },
    {
      "cmd": "eval 'p2p held decline'",
      "verb": "held decline"
    },
    {
      "cmd": "p2p relays add",
      "verb": "relays add"
    },
    {
      "cmd": "p2p --json relays --yes add arg1",
      "verb": "relays add"
    },
    {
      "cmd": "p2p relays add arg1 --json --yes",
      "verb": "relays add"
    },
    {
      "cmd": "bash -c 'p2p relays add arg1'",
      "verb": "relays add"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p relays add --yes\"",
      "verb": "relays add"
    },
    {
      "cmd": "nohup p2p relays add arg1",
      "verb": "relays add"
    },
    {
      "cmd": "nice -n 5 p2p relays add",
      "verb": "relays add"
    },
    {
      "cmd": "timeout 30 p2p relays add --json",
      "verb": "relays add"
    },
    {
      "cmd": "true && p2p relays add",
      "verb": "relays add"
    },
    {
      "cmd": "npx -y @peer2peer/cli relays add",
      "verb": "relays add"
    },
    {
      "cmd": "env -S 'p2p relays add arg1'",
      "verb": "relays add"
    },
    {
      "cmd": "eval 'p2p relays add'",
      "verb": "relays add"
    },
    {
      "cmd": "p2p relays remove",
      "verb": "relays remove"
    },
    {
      "cmd": "p2p --json relays --yes remove arg1",
      "verb": "relays remove"
    },
    {
      "cmd": "p2p relays remove arg1 --json --yes",
      "verb": "relays remove"
    },
    {
      "cmd": "bash -c 'p2p relays remove arg1'",
      "verb": "relays remove"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p relays remove --yes\"",
      "verb": "relays remove"
    },
    {
      "cmd": "nohup p2p relays remove arg1",
      "verb": "relays remove"
    },
    {
      "cmd": "nice -n 5 p2p relays remove",
      "verb": "relays remove"
    },
    {
      "cmd": "timeout 30 p2p relays remove --json",
      "verb": "relays remove"
    },
    {
      "cmd": "true && p2p relays remove",
      "verb": "relays remove"
    },
    {
      "cmd": "npx -y @peer2peer/cli relays remove",
      "verb": "relays remove"
    },
    {
      "cmd": "env -S 'p2p relays remove arg1'",
      "verb": "relays remove"
    },
    {
      "cmd": "eval 'p2p relays remove'",
      "verb": "relays remove"
    },
    {
      "cmd": "p2p circle invite",
      "verb": "circle invite"
    },
    {
      "cmd": "p2p --json circle --yes invite arg1",
      "verb": "circle invite"
    },
    {
      "cmd": "p2p circle invite arg1 --json --yes",
      "verb": "circle invite"
    },
    {
      "cmd": "bash -c 'p2p circle invite arg1'",
      "verb": "circle invite"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle invite --yes\"",
      "verb": "circle invite"
    },
    {
      "cmd": "nohup p2p circle invite arg1",
      "verb": "circle invite"
    },
    {
      "cmd": "nice -n 5 p2p circle invite",
      "verb": "circle invite"
    },
    {
      "cmd": "timeout 30 p2p circle invite --json",
      "verb": "circle invite"
    },
    {
      "cmd": "true && p2p circle invite",
      "verb": "circle invite"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle invite",
      "verb": "circle invite"
    },
    {
      "cmd": "env -S 'p2p circle invite arg1'",
      "verb": "circle invite"
    },
    {
      "cmd": "eval 'p2p circle invite'",
      "verb": "circle invite"
    },
    {
      "cmd": "p2p circle join",
      "verb": "circle join"
    },
    {
      "cmd": "p2p --json circle --yes join arg1",
      "verb": "circle join"
    },
    {
      "cmd": "p2p circle join arg1 --json --yes",
      "verb": "circle join"
    },
    {
      "cmd": "bash -c 'p2p circle join arg1'",
      "verb": "circle join"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle join --yes\"",
      "verb": "circle join"
    },
    {
      "cmd": "nohup p2p circle join arg1",
      "verb": "circle join"
    },
    {
      "cmd": "nice -n 5 p2p circle join",
      "verb": "circle join"
    },
    {
      "cmd": "timeout 30 p2p circle join --json",
      "verb": "circle join"
    },
    {
      "cmd": "true && p2p circle join",
      "verb": "circle join"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle join",
      "verb": "circle join"
    },
    {
      "cmd": "env -S 'p2p circle join arg1'",
      "verb": "circle join"
    },
    {
      "cmd": "eval 'p2p circle join'",
      "verb": "circle join"
    },
    {
      "cmd": "p2p circle create",
      "verb": "circle create"
    },
    {
      "cmd": "p2p --json circle --yes create arg1",
      "verb": "circle create"
    },
    {
      "cmd": "p2p circle create arg1 --json --yes",
      "verb": "circle create"
    },
    {
      "cmd": "bash -c 'p2p circle create arg1'",
      "verb": "circle create"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle create --yes\"",
      "verb": "circle create"
    },
    {
      "cmd": "nohup p2p circle create arg1",
      "verb": "circle create"
    },
    {
      "cmd": "nice -n 5 p2p circle create",
      "verb": "circle create"
    },
    {
      "cmd": "timeout 30 p2p circle create --json",
      "verb": "circle create"
    },
    {
      "cmd": "true && p2p circle create",
      "verb": "circle create"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle create",
      "verb": "circle create"
    },
    {
      "cmd": "env -S 'p2p circle create arg1'",
      "verb": "circle create"
    },
    {
      "cmd": "eval 'p2p circle create'",
      "verb": "circle create"
    },
    {
      "cmd": "p2p circle leave",
      "verb": "circle leave"
    },
    {
      "cmd": "p2p --json circle --yes leave arg1",
      "verb": "circle leave"
    },
    {
      "cmd": "p2p circle leave arg1 --json --yes",
      "verb": "circle leave"
    },
    {
      "cmd": "bash -c 'p2p circle leave arg1'",
      "verb": "circle leave"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle leave --yes\"",
      "verb": "circle leave"
    },
    {
      "cmd": "nohup p2p circle leave arg1",
      "verb": "circle leave"
    },
    {
      "cmd": "nice -n 5 p2p circle leave",
      "verb": "circle leave"
    },
    {
      "cmd": "timeout 30 p2p circle leave --json",
      "verb": "circle leave"
    },
    {
      "cmd": "true && p2p circle leave",
      "verb": "circle leave"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle leave",
      "verb": "circle leave"
    },
    {
      "cmd": "env -S 'p2p circle leave arg1'",
      "verb": "circle leave"
    },
    {
      "cmd": "eval 'p2p circle leave'",
      "verb": "circle leave"
    },
    {
      "cmd": "p2p circle propose",
      "verb": "circle propose"
    },
    {
      "cmd": "p2p --json circle --yes propose arg1",
      "verb": "circle propose"
    },
    {
      "cmd": "p2p circle propose arg1 --json --yes",
      "verb": "circle propose"
    },
    {
      "cmd": "bash -c 'p2p circle propose arg1'",
      "verb": "circle propose"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle propose --yes\"",
      "verb": "circle propose"
    },
    {
      "cmd": "nohup p2p circle propose arg1",
      "verb": "circle propose"
    },
    {
      "cmd": "nice -n 5 p2p circle propose",
      "verb": "circle propose"
    },
    {
      "cmd": "timeout 30 p2p circle propose --json",
      "verb": "circle propose"
    },
    {
      "cmd": "true && p2p circle propose",
      "verb": "circle propose"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle propose",
      "verb": "circle propose"
    },
    {
      "cmd": "env -S 'p2p circle propose arg1'",
      "verb": "circle propose"
    },
    {
      "cmd": "eval 'p2p circle propose'",
      "verb": "circle propose"
    },
    {
      "cmd": "p2p circle transfer",
      "verb": "circle transfer"
    },
    {
      "cmd": "p2p --json circle --yes transfer arg1",
      "verb": "circle transfer"
    },
    {
      "cmd": "p2p circle transfer arg1 --json --yes",
      "verb": "circle transfer"
    },
    {
      "cmd": "bash -c 'p2p circle transfer arg1'",
      "verb": "circle transfer"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle transfer --yes\"",
      "verb": "circle transfer"
    },
    {
      "cmd": "nohup p2p circle transfer arg1",
      "verb": "circle transfer"
    },
    {
      "cmd": "nice -n 5 p2p circle transfer",
      "verb": "circle transfer"
    },
    {
      "cmd": "timeout 30 p2p circle transfer --json",
      "verb": "circle transfer"
    },
    {
      "cmd": "true && p2p circle transfer",
      "verb": "circle transfer"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle transfer",
      "verb": "circle transfer"
    },
    {
      "cmd": "env -S 'p2p circle transfer arg1'",
      "verb": "circle transfer"
    },
    {
      "cmd": "eval 'p2p circle transfer'",
      "verb": "circle transfer"
    },
    {
      "cmd": "p2p circle policy",
      "verb": "circle policy"
    },
    {
      "cmd": "p2p --json circle --yes policy arg1",
      "verb": "circle policy"
    },
    {
      "cmd": "p2p circle policy arg1 --json --yes",
      "verb": "circle policy"
    },
    {
      "cmd": "bash -c 'p2p circle policy arg1'",
      "verb": "circle policy"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle policy --yes\"",
      "verb": "circle policy"
    },
    {
      "cmd": "nohup p2p circle policy arg1",
      "verb": "circle policy"
    },
    {
      "cmd": "nice -n 5 p2p circle policy",
      "verb": "circle policy"
    },
    {
      "cmd": "timeout 30 p2p circle policy --json",
      "verb": "circle policy"
    },
    {
      "cmd": "true && p2p circle policy",
      "verb": "circle policy"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle policy",
      "verb": "circle policy"
    },
    {
      "cmd": "env -S 'p2p circle policy arg1'",
      "verb": "circle policy"
    },
    {
      "cmd": "eval 'p2p circle policy'",
      "verb": "circle policy"
    },
    {
      "cmd": "p2p circle default",
      "verb": "circle default"
    },
    {
      "cmd": "p2p --json circle --yes default arg1",
      "verb": "circle default"
    },
    {
      "cmd": "p2p circle default arg1 --json --yes",
      "verb": "circle default"
    },
    {
      "cmd": "bash -c 'p2p circle default arg1'",
      "verb": "circle default"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle default --yes\"",
      "verb": "circle default"
    },
    {
      "cmd": "nohup p2p circle default arg1",
      "verb": "circle default"
    },
    {
      "cmd": "nice -n 5 p2p circle default",
      "verb": "circle default"
    },
    {
      "cmd": "timeout 30 p2p circle default --json",
      "verb": "circle default"
    },
    {
      "cmd": "true && p2p circle default",
      "verb": "circle default"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle default",
      "verb": "circle default"
    },
    {
      "cmd": "env -S 'p2p circle default arg1'",
      "verb": "circle default"
    },
    {
      "cmd": "eval 'p2p circle default'",
      "verb": "circle default"
    },
    {
      "cmd": "p2p circle hold",
      "verb": "circle hold"
    },
    {
      "cmd": "p2p --json circle --yes hold arg1",
      "verb": "circle hold"
    },
    {
      "cmd": "p2p circle hold arg1 --json --yes",
      "verb": "circle hold"
    },
    {
      "cmd": "bash -c 'p2p circle hold arg1'",
      "verb": "circle hold"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p circle hold --yes\"",
      "verb": "circle hold"
    },
    {
      "cmd": "nohup p2p circle hold arg1",
      "verb": "circle hold"
    },
    {
      "cmd": "nice -n 5 p2p circle hold",
      "verb": "circle hold"
    },
    {
      "cmd": "timeout 30 p2p circle hold --json",
      "verb": "circle hold"
    },
    {
      "cmd": "true && p2p circle hold",
      "verb": "circle hold"
    },
    {
      "cmd": "npx -y @peer2peer/cli circle hold",
      "verb": "circle hold"
    },
    {
      "cmd": "env -S 'p2p circle hold arg1'",
      "verb": "circle hold"
    },
    {
      "cmd": "eval 'p2p circle hold'",
      "verb": "circle hold"
    },
    {
      "cmd": "p2p devices revoke",
      "verb": "devices revoke"
    },
    {
      "cmd": "p2p --json devices --yes revoke arg1",
      "verb": "devices revoke"
    },
    {
      "cmd": "p2p devices revoke arg1 --json --yes",
      "verb": "devices revoke"
    },
    {
      "cmd": "bash -c 'p2p devices revoke arg1'",
      "verb": "devices revoke"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p devices revoke --yes\"",
      "verb": "devices revoke"
    },
    {
      "cmd": "nohup p2p devices revoke arg1",
      "verb": "devices revoke"
    },
    {
      "cmd": "nice -n 5 p2p devices revoke",
      "verb": "devices revoke"
    },
    {
      "cmd": "timeout 30 p2p devices revoke --json",
      "verb": "devices revoke"
    },
    {
      "cmd": "true && p2p devices revoke",
      "verb": "devices revoke"
    },
    {
      "cmd": "npx -y @peer2peer/cli devices revoke",
      "verb": "devices revoke"
    },
    {
      "cmd": "env -S 'p2p devices revoke arg1'",
      "verb": "devices revoke"
    },
    {
      "cmd": "eval 'p2p devices revoke'",
      "verb": "devices revoke"
    },
    {
      "cmd": "p2p session roster",
      "verb": "session roster"
    },
    {
      "cmd": "p2p --json session --yes roster arg1",
      "verb": "session roster"
    },
    {
      "cmd": "p2p session roster arg1 --json --yes",
      "verb": "session roster"
    },
    {
      "cmd": "bash -c 'p2p session roster arg1'",
      "verb": "session roster"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p session roster --yes\"",
      "verb": "session roster"
    },
    {
      "cmd": "nohup p2p session roster arg1",
      "verb": "session roster"
    },
    {
      "cmd": "nice -n 5 p2p session roster",
      "verb": "session roster"
    },
    {
      "cmd": "timeout 30 p2p session roster --json",
      "verb": "session roster"
    },
    {
      "cmd": "true && p2p session roster",
      "verb": "session roster"
    },
    {
      "cmd": "npx -y @peer2peer/cli session roster",
      "verb": "session roster"
    },
    {
      "cmd": "env -S 'p2p session roster arg1'",
      "verb": "session roster"
    },
    {
      "cmd": "eval 'p2p session roster'",
      "verb": "session roster"
    },
    {
      "cmd": "p2p identity republish",
      "verb": "identity republish"
    },
    {
      "cmd": "p2p --json identity --yes republish arg1",
      "verb": "identity republish"
    },
    {
      "cmd": "p2p identity republish arg1 --json --yes",
      "verb": "identity republish"
    },
    {
      "cmd": "bash -c 'p2p identity republish arg1'",
      "verb": "identity republish"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p identity republish --yes\"",
      "verb": "identity republish"
    },
    {
      "cmd": "nohup p2p identity republish arg1",
      "verb": "identity republish"
    },
    {
      "cmd": "nice -n 5 p2p identity republish",
      "verb": "identity republish"
    },
    {
      "cmd": "timeout 30 p2p identity republish --json",
      "verb": "identity republish"
    },
    {
      "cmd": "true && p2p identity republish",
      "verb": "identity republish"
    },
    {
      "cmd": "npx -y @peer2peer/cli identity republish",
      "verb": "identity republish"
    },
    {
      "cmd": "env -S 'p2p identity republish arg1'",
      "verb": "identity republish"
    },
    {
      "cmd": "eval 'p2p identity republish'",
      "verb": "identity republish"
    },
    {
      "cmd": "p2p identity rotate",
      "verb": "identity rotate"
    },
    {
      "cmd": "p2p --json identity --yes rotate arg1",
      "verb": "identity rotate"
    },
    {
      "cmd": "p2p identity rotate arg1 --json --yes",
      "verb": "identity rotate"
    },
    {
      "cmd": "bash -c 'p2p identity rotate arg1'",
      "verb": "identity rotate"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p identity rotate --yes\"",
      "verb": "identity rotate"
    },
    {
      "cmd": "nohup p2p identity rotate arg1",
      "verb": "identity rotate"
    },
    {
      "cmd": "nice -n 5 p2p identity rotate",
      "verb": "identity rotate"
    },
    {
      "cmd": "timeout 30 p2p identity rotate --json",
      "verb": "identity rotate"
    },
    {
      "cmd": "true && p2p identity rotate",
      "verb": "identity rotate"
    },
    {
      "cmd": "npx -y @peer2peer/cli identity rotate",
      "verb": "identity rotate"
    },
    {
      "cmd": "env -S 'p2p identity rotate arg1'",
      "verb": "identity rotate"
    },
    {
      "cmd": "eval 'p2p identity rotate'",
      "verb": "identity rotate"
    },
    {
      "cmd": "p2p identity follow",
      "verb": "identity follow"
    },
    {
      "cmd": "p2p --json identity --yes follow arg1",
      "verb": "identity follow"
    },
    {
      "cmd": "p2p identity follow arg1 --json --yes",
      "verb": "identity follow"
    },
    {
      "cmd": "bash -c 'p2p identity follow arg1'",
      "verb": "identity follow"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p identity follow --yes\"",
      "verb": "identity follow"
    },
    {
      "cmd": "nohup p2p identity follow arg1",
      "verb": "identity follow"
    },
    {
      "cmd": "nice -n 5 p2p identity follow",
      "verb": "identity follow"
    },
    {
      "cmd": "timeout 30 p2p identity follow --json",
      "verb": "identity follow"
    },
    {
      "cmd": "true && p2p identity follow",
      "verb": "identity follow"
    },
    {
      "cmd": "npx -y @peer2peer/cli identity follow",
      "verb": "identity follow"
    },
    {
      "cmd": "env -S 'p2p identity follow arg1'",
      "verb": "identity follow"
    },
    {
      "cmd": "eval 'p2p identity follow'",
      "verb": "identity follow"
    },
    {
      "cmd": "p2p identity dispute",
      "verb": "identity dispute"
    },
    {
      "cmd": "p2p --json identity --yes dispute arg1",
      "verb": "identity dispute"
    },
    {
      "cmd": "p2p identity dispute arg1 --json --yes",
      "verb": "identity dispute"
    },
    {
      "cmd": "bash -c 'p2p identity dispute arg1'",
      "verb": "identity dispute"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p identity dispute --yes\"",
      "verb": "identity dispute"
    },
    {
      "cmd": "nohup p2p identity dispute arg1",
      "verb": "identity dispute"
    },
    {
      "cmd": "nice -n 5 p2p identity dispute",
      "verb": "identity dispute"
    },
    {
      "cmd": "timeout 30 p2p identity dispute --json",
      "verb": "identity dispute"
    },
    {
      "cmd": "true && p2p identity dispute",
      "verb": "identity dispute"
    },
    {
      "cmd": "npx -y @peer2peer/cli identity dispute",
      "verb": "identity dispute"
    },
    {
      "cmd": "env -S 'p2p identity dispute arg1'",
      "verb": "identity dispute"
    },
    {
      "cmd": "eval 'p2p identity dispute'",
      "verb": "identity dispute"
    },
    {
      "cmd": "p2p profile set",
      "verb": "profile set"
    },
    {
      "cmd": "p2p --json profile --yes set arg1",
      "verb": "profile set"
    },
    {
      "cmd": "p2p profile set arg1 --json --yes",
      "verb": "profile set"
    },
    {
      "cmd": "bash -c 'p2p profile set arg1'",
      "verb": "profile set"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p profile set --yes\"",
      "verb": "profile set"
    },
    {
      "cmd": "nohup p2p profile set arg1",
      "verb": "profile set"
    },
    {
      "cmd": "nice -n 5 p2p profile set",
      "verb": "profile set"
    },
    {
      "cmd": "timeout 30 p2p profile set --json",
      "verb": "profile set"
    },
    {
      "cmd": "true && p2p profile set",
      "verb": "profile set"
    },
    {
      "cmd": "npx -y @peer2peer/cli profile set",
      "verb": "profile set"
    },
    {
      "cmd": "env -S 'p2p profile set arg1'",
      "verb": "profile set"
    },
    {
      "cmd": "eval 'p2p profile set'",
      "verb": "profile set"
    },
    {
      "cmd": "p2p proof add",
      "verb": "proof add"
    },
    {
      "cmd": "p2p --json proof --yes add arg1",
      "verb": "proof add"
    },
    {
      "cmd": "p2p proof add arg1 --json --yes",
      "verb": "proof add"
    },
    {
      "cmd": "bash -c 'p2p proof add arg1'",
      "verb": "proof add"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p proof add --yes\"",
      "verb": "proof add"
    },
    {
      "cmd": "nohup p2p proof add arg1",
      "verb": "proof add"
    },
    {
      "cmd": "nice -n 5 p2p proof add",
      "verb": "proof add"
    },
    {
      "cmd": "timeout 30 p2p proof add --json",
      "verb": "proof add"
    },
    {
      "cmd": "true && p2p proof add",
      "verb": "proof add"
    },
    {
      "cmd": "npx -y @peer2peer/cli proof add",
      "verb": "proof add"
    },
    {
      "cmd": "env -S 'p2p proof add arg1'",
      "verb": "proof add"
    },
    {
      "cmd": "eval 'p2p proof add'",
      "verb": "proof add"
    },
    {
      "cmd": "p2p invites revoke",
      "verb": "invites revoke"
    },
    {
      "cmd": "p2p --json invites --yes revoke arg1",
      "verb": "invites revoke"
    },
    {
      "cmd": "p2p invites revoke arg1 --json --yes",
      "verb": "invites revoke"
    },
    {
      "cmd": "bash -c 'p2p invites revoke arg1'",
      "verb": "invites revoke"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p invites revoke --yes\"",
      "verb": "invites revoke"
    },
    {
      "cmd": "nohup p2p invites revoke arg1",
      "verb": "invites revoke"
    },
    {
      "cmd": "nice -n 5 p2p invites revoke",
      "verb": "invites revoke"
    },
    {
      "cmd": "timeout 30 p2p invites revoke --json",
      "verb": "invites revoke"
    },
    {
      "cmd": "true && p2p invites revoke",
      "verb": "invites revoke"
    },
    {
      "cmd": "npx -y @peer2peer/cli invites revoke",
      "verb": "invites revoke"
    },
    {
      "cmd": "env -S 'p2p invites revoke arg1'",
      "verb": "invites revoke"
    },
    {
      "cmd": "eval 'p2p invites revoke'",
      "verb": "invites revoke"
    },
    {
      "cmd": "p2p codex install",
      "verb": "codex install"
    },
    {
      "cmd": "p2p --json codex --yes install arg1",
      "verb": "codex install"
    },
    {
      "cmd": "p2p codex install arg1 --json --yes",
      "verb": "codex install"
    },
    {
      "cmd": "bash -c 'p2p codex install arg1'",
      "verb": "codex install"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p codex install --yes\"",
      "verb": "codex install"
    },
    {
      "cmd": "nohup p2p codex install arg1",
      "verb": "codex install"
    },
    {
      "cmd": "nice -n 5 p2p codex install",
      "verb": "codex install"
    },
    {
      "cmd": "timeout 30 p2p codex install --json",
      "verb": "codex install"
    },
    {
      "cmd": "true && p2p codex install",
      "verb": "codex install"
    },
    {
      "cmd": "npx -y @peer2peer/cli codex install",
      "verb": "codex install"
    },
    {
      "cmd": "env -S 'p2p codex install arg1'",
      "verb": "codex install"
    },
    {
      "cmd": "eval 'p2p codex install'",
      "verb": "codex install"
    },
    {
      "cmd": "p2p codex release",
      "verb": "codex release"
    },
    {
      "cmd": "p2p --json codex --yes release arg1",
      "verb": "codex release"
    },
    {
      "cmd": "p2p codex release arg1 --json --yes",
      "verb": "codex release"
    },
    {
      "cmd": "bash -c 'p2p codex release arg1'",
      "verb": "codex release"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p codex release --yes\"",
      "verb": "codex release"
    },
    {
      "cmd": "nohup p2p codex release arg1",
      "verb": "codex release"
    },
    {
      "cmd": "nice -n 5 p2p codex release",
      "verb": "codex release"
    },
    {
      "cmd": "timeout 30 p2p codex release --json",
      "verb": "codex release"
    },
    {
      "cmd": "true && p2p codex release",
      "verb": "codex release"
    },
    {
      "cmd": "npx -y @peer2peer/cli codex release",
      "verb": "codex release"
    },
    {
      "cmd": "env -S 'p2p codex release arg1'",
      "verb": "codex release"
    },
    {
      "cmd": "eval 'p2p codex release'",
      "verb": "codex release"
    },
    {
      "cmd": "p2p codex decline",
      "verb": "codex decline"
    },
    {
      "cmd": "p2p --json codex --yes decline arg1",
      "verb": "codex decline"
    },
    {
      "cmd": "p2p codex decline arg1 --json --yes",
      "verb": "codex decline"
    },
    {
      "cmd": "bash -c 'p2p codex decline arg1'",
      "verb": "codex decline"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p codex decline --yes\"",
      "verb": "codex decline"
    },
    {
      "cmd": "nohup p2p codex decline arg1",
      "verb": "codex decline"
    },
    {
      "cmd": "nice -n 5 p2p codex decline",
      "verb": "codex decline"
    },
    {
      "cmd": "timeout 30 p2p codex decline --json",
      "verb": "codex decline"
    },
    {
      "cmd": "true && p2p codex decline",
      "verb": "codex decline"
    },
    {
      "cmd": "npx -y @peer2peer/cli codex decline",
      "verb": "codex decline"
    },
    {
      "cmd": "env -S 'p2p codex decline arg1'",
      "verb": "codex decline"
    },
    {
      "cmd": "eval 'p2p codex decline'",
      "verb": "codex decline"
    },
    {
      "cmd": "p2p ix note",
      "verb": "ix note"
    },
    {
      "cmd": "p2p --json ix --yes note arg1",
      "verb": "ix note"
    },
    {
      "cmd": "p2p ix note arg1 --json --yes",
      "verb": "ix note"
    },
    {
      "cmd": "bash -c 'p2p ix note arg1'",
      "verb": "ix note"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix note --yes\"",
      "verb": "ix note"
    },
    {
      "cmd": "nohup p2p ix note arg1",
      "verb": "ix note"
    },
    {
      "cmd": "nice -n 5 p2p ix note",
      "verb": "ix note"
    },
    {
      "cmd": "timeout 30 p2p ix note --json",
      "verb": "ix note"
    },
    {
      "cmd": "true && p2p ix note",
      "verb": "ix note"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix note",
      "verb": "ix note"
    },
    {
      "cmd": "env -S 'p2p ix note arg1'",
      "verb": "ix note"
    },
    {
      "cmd": "eval 'p2p ix note'",
      "verb": "ix note"
    },
    {
      "cmd": "p2p ix subgraph",
      "verb": "ix subgraph"
    },
    {
      "cmd": "p2p --json ix --yes subgraph arg1",
      "verb": "ix subgraph"
    },
    {
      "cmd": "p2p ix subgraph arg1 --json --yes",
      "verb": "ix subgraph"
    },
    {
      "cmd": "bash -c 'p2p ix subgraph arg1'",
      "verb": "ix subgraph"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix subgraph --yes\"",
      "verb": "ix subgraph"
    },
    {
      "cmd": "nohup p2p ix subgraph arg1",
      "verb": "ix subgraph"
    },
    {
      "cmd": "nice -n 5 p2p ix subgraph",
      "verb": "ix subgraph"
    },
    {
      "cmd": "timeout 30 p2p ix subgraph --json",
      "verb": "ix subgraph"
    },
    {
      "cmd": "true && p2p ix subgraph",
      "verb": "ix subgraph"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix subgraph",
      "verb": "ix subgraph"
    },
    {
      "cmd": "env -S 'p2p ix subgraph arg1'",
      "verb": "ix subgraph"
    },
    {
      "cmd": "eval 'p2p ix subgraph'",
      "verb": "ix subgraph"
    },
    {
      "cmd": "p2p ix impact",
      "verb": "ix impact"
    },
    {
      "cmd": "p2p --json ix --yes impact arg1",
      "verb": "ix impact"
    },
    {
      "cmd": "p2p ix impact arg1 --json --yes",
      "verb": "ix impact"
    },
    {
      "cmd": "bash -c 'p2p ix impact arg1'",
      "verb": "ix impact"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix impact --yes\"",
      "verb": "ix impact"
    },
    {
      "cmd": "nohup p2p ix impact arg1",
      "verb": "ix impact"
    },
    {
      "cmd": "nice -n 5 p2p ix impact",
      "verb": "ix impact"
    },
    {
      "cmd": "timeout 30 p2p ix impact --json",
      "verb": "ix impact"
    },
    {
      "cmd": "true && p2p ix impact",
      "verb": "ix impact"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix impact",
      "verb": "ix impact"
    },
    {
      "cmd": "env -S 'p2p ix impact arg1'",
      "verb": "ix impact"
    },
    {
      "cmd": "eval 'p2p ix impact'",
      "verb": "ix impact"
    },
    {
      "cmd": "p2p ix config",
      "verb": "ix config"
    },
    {
      "cmd": "p2p --json ix --yes config arg1",
      "verb": "ix config"
    },
    {
      "cmd": "p2p ix config arg1 --json --yes",
      "verb": "ix config"
    },
    {
      "cmd": "bash -c 'p2p ix config arg1'",
      "verb": "ix config"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p ix config --yes\"",
      "verb": "ix config"
    },
    {
      "cmd": "nohup p2p ix config arg1",
      "verb": "ix config"
    },
    {
      "cmd": "nice -n 5 p2p ix config",
      "verb": "ix config"
    },
    {
      "cmd": "timeout 30 p2p ix config --json",
      "verb": "ix config"
    },
    {
      "cmd": "true && p2p ix config",
      "verb": "ix config"
    },
    {
      "cmd": "npx -y @peer2peer/cli ix config",
      "verb": "ix config"
    },
    {
      "cmd": "env -S 'p2p ix config arg1'",
      "verb": "ix config"
    },
    {
      "cmd": "eval 'p2p ix config'",
      "verb": "ix config"
    },
    {
      "cmd": "p2p project share",
      "verb": "project share"
    },
    {
      "cmd": "p2p --json project --yes share arg1",
      "verb": "project share"
    },
    {
      "cmd": "p2p project share arg1 --json --yes",
      "verb": "project share"
    },
    {
      "cmd": "bash -c 'p2p project share arg1'",
      "verb": "project share"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p project share --yes\"",
      "verb": "project share"
    },
    {
      "cmd": "nohup p2p project share arg1",
      "verb": "project share"
    },
    {
      "cmd": "nice -n 5 p2p project share",
      "verb": "project share"
    },
    {
      "cmd": "timeout 30 p2p project share --json",
      "verb": "project share"
    },
    {
      "cmd": "true && p2p project share",
      "verb": "project share"
    },
    {
      "cmd": "npx -y @peer2peer/cli project share",
      "verb": "project share"
    },
    {
      "cmd": "env -S 'p2p project share arg1'",
      "verb": "project share"
    },
    {
      "cmd": "eval 'p2p project share'",
      "verb": "project share"
    },
    {
      "cmd": "p2p project private",
      "verb": "project private"
    },
    {
      "cmd": "p2p --json project --yes private arg1",
      "verb": "project private"
    },
    {
      "cmd": "p2p project private arg1 --json --yes",
      "verb": "project private"
    },
    {
      "cmd": "bash -c 'p2p project private arg1'",
      "verb": "project private"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p project private --yes\"",
      "verb": "project private"
    },
    {
      "cmd": "nohup p2p project private arg1",
      "verb": "project private"
    },
    {
      "cmd": "nice -n 5 p2p project private",
      "verb": "project private"
    },
    {
      "cmd": "timeout 30 p2p project private --json",
      "verb": "project private"
    },
    {
      "cmd": "true && p2p project private",
      "verb": "project private"
    },
    {
      "cmd": "npx -y @peer2peer/cli project private",
      "verb": "project private"
    },
    {
      "cmd": "env -S 'p2p project private arg1'",
      "verb": "project private"
    },
    {
      "cmd": "eval 'p2p project private'",
      "verb": "project private"
    },
    {
      "cmd": "p2p status",
      "verb": "status"
    },
    {
      "cmd": "p2p status --json",
      "verb": "status"
    },
    {
      "cmd": "p2p status arg1 --json --yes",
      "verb": "status"
    },
    {
      "cmd": "bash -c 'p2p status arg1'",
      "verb": "status"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p status --yes\"",
      "verb": "status"
    },
    {
      "cmd": "nohup p2p status arg1",
      "verb": "status"
    },
    {
      "cmd": "nice -n 5 p2p status",
      "verb": "status"
    },
    {
      "cmd": "timeout 30 p2p status --json",
      "verb": "status"
    },
    {
      "cmd": "true && p2p status",
      "verb": "status"
    },
    {
      "cmd": "npx -y @peer2peer/cli status",
      "verb": "status"
    },
    {
      "cmd": "env -S 'p2p status arg1'",
      "verb": "status"
    },
    {
      "cmd": "eval 'p2p status'",
      "verb": "status"
    },
    {
      "cmd": "p2p receipt",
      "verb": "receipt"
    },
    {
      "cmd": "p2p receipt --json",
      "verb": "receipt"
    },
    {
      "cmd": "p2p receipt arg1 --json --yes",
      "verb": "receipt"
    },
    {
      "cmd": "bash -c 'p2p receipt arg1'",
      "verb": "receipt"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p receipt --yes\"",
      "verb": "receipt"
    },
    {
      "cmd": "nohup p2p receipt arg1",
      "verb": "receipt"
    },
    {
      "cmd": "nice -n 5 p2p receipt",
      "verb": "receipt"
    },
    {
      "cmd": "timeout 30 p2p receipt --json",
      "verb": "receipt"
    },
    {
      "cmd": "true && p2p receipt",
      "verb": "receipt"
    },
    {
      "cmd": "npx -y @peer2peer/cli receipt",
      "verb": "receipt"
    },
    {
      "cmd": "env -S 'p2p receipt arg1'",
      "verb": "receipt"
    },
    {
      "cmd": "eval 'p2p receipt'",
      "verb": "receipt"
    },
    {
      "cmd": "p2p own-agents",
      "verb": "own-agents"
    },
    {
      "cmd": "p2p own-agents --json",
      "verb": "own-agents"
    },
    {
      "cmd": "p2p own-agents arg1 --json --yes",
      "verb": "own-agents"
    },
    {
      "cmd": "bash -c 'p2p own-agents arg1'",
      "verb": "own-agents"
    },
    {
      "cmd": "sh -c \"cd /tmp && p2p own-agents --yes\"",
      "verb": "own-agents"
    },
    {
      "cmd": "nohup p2p own-agents arg1",
      "verb": "own-agents"
    },
    {
      "cmd": "nice -n 5 p2p own-agents",
      "verb": "own-agents"
    },
    {
      "cmd": "timeout 30 p2p own-agents --json",
      "verb": "own-agents"
    },
    {
      "cmd": "true && p2p own-agents",
      "verb": "own-agents"
    },
    {
      "cmd": "npx -y @peer2peer/cli own-agents",
      "verb": "own-agents"
    },
    {
      "cmd": "env -S 'p2p own-agents arg1'",
      "verb": "own-agents"
    },
    {
      "cmd": "eval 'p2p own-agents'",
      "verb": "own-agents"
    },
    {
      "cmd": "p2p identity rotate --resume --yes --backup-file /tmp/k.txt",
      "verb": "identity rotate"
    },
    {
      "cmd": "p2p identity rotate --plan",
      "verb": "identity rotate"
    },
    {
      "cmd": "p2p identity follow r123",
      "verb": "identity follow"
    },
    {
      "cmd": "p2p identity dispute r123 --neither",
      "verb": "identity dispute"
    },
    {
      "cmd": "p2p trust add alice@abcd1234",
      "verb": "trust add"
    },
    {
      "cmd": "p2p trust remove circle:team",
      "verb": "trust remove"
    },
    {
      "cmd": "p2p extensions enable ix",
      "verb": "extensions enable"
    },
    {
      "cmd": "p2p extensions disable ix",
      "verb": "extensions disable"
    },
    {
      "cmd": "p2p invites revoke ABCD",
      "verb": "invites revoke"
    },
    {
      "cmd": "p2p circle hold c1 off",
      "verb": "circle hold"
    },
    {
      "cmd": "p2p ix import e1 --yes --shown 0123",
      "verb": "ix import"
    },
    {
      "cmd": "p2p ix resolve e1 --yes --any-repo",
      "verb": "ix resolve"
    },
    {
      "cmd": "p2p ix note --from-session s1 --to bob hi",
      "verb": "ix note"
    },
    {
      "cmd": "p2p ix config names=plain",
      "verb": "ix config"
    },
    {
      "cmd": "p2p --session s1 tui",
      "verb": "tui"
    },
    {
      "cmd": "p2p unblock mallory@abcd1234",
      "verb": "unblock"
    },
    {
      "cmd": "p2p status --session s1 --state busy",
      "verb": "status"
    },
    {
      "cmd": "p2p ix footprint --publish --from-session s1",
      "verb": "ix footprint --publish"
    },
    {
      "cmd": "p2p ix footprint --names=plain",
      "verb": "ix footprint --publish"
    },
    {
      "cmd": "bash -c 'p2p ix footprint --force'",
      "verb": "ix footprint --publish"
    },
    {
      "cmd": "p2p trust ls",
      "verb": null
    },
    {
      "cmd": "p2p circle ls",
      "verb": null
    },
    {
      "cmd": "p2p invites",
      "verb": null
    },
    {
      "cmd": "p2p ix footprint",
      "verb": null
    },
    {
      "cmd": "p2p ix inbox",
      "verb": null
    },
    {
      "cmd": "p2p extensions",
      "verb": null
    },
    {
      "cmd": "p2p doctor",
      "verb": null
    },
    {
      "cmd": "p2p whoami",
      "verb": null
    },
    {
      "cmd": "p2p identity show",
      "verb": null
    }
  ]
}
