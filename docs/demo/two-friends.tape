# Peer2Peer hero demo: two people, two agent sessions, one local relay.
# Render from the repository root:   vhs docs/demo/two-friends.tape
# Needs core, relay and codex-bridge built (see docs/demo/README.md). No network, no accounts.

Output docs/demo/two-friends.gif

Set Shell "bash"
Set FontSize 18
Set Width 1280
Set Height 760
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
# Wait for the prompt after each command, so slow steps (the join) never garble typed-ahead input.
Set WaitPattern /\$ ?$/
Set WaitTimeout 60s

Hide
Type "export PS1='$ ' && source docs/demo/demo-env.sh && clear"
Enter
Sleep 2s
Show

Type "# Ann makes a key (no account) and a circle for her team"
Enter
Wait
Type "ann setup --name ann --no-backup"
Enter
Wait
Sleep 2s
Type "ann circle default $(ann circle create api-team --json | json cid)"
Enter
Wait
Sleep 2s

Type "# Ann invites Ben with a one-time code"
Enter
Wait
Type "CODE=$(ann invite ben --json | json code); echo $CODE"
Enter
Wait
Sleep 2s
Type "clear"
Enter
Wait

Type "# Ben joins: that creates his identity, friends them, and adds him to the circle"
Enter
Wait
Type "ben join $CODE --name ben"
Enter
Wait
Sleep 3s
Type "ann friends >/dev/null"
Enter
Wait
Sleep 1s
Type "clear"
Enter
Wait

Type "# Both agent sessions share what they're working on"
Enter
Wait
Type "ben status --session s-ben --state busy --label api --repo api --branch rate-limit --summary 'Adding rate limits to login' --file src/auth/token.ts --file src/api/login.ts"
Enter
Wait
Sleep 2s
Type "ann status --session s-ann --state busy --label api --repo api --branch main --summary 'Moving refreshToken() into its own module' --file src/auth/token.ts"
Enter
Wait
Sleep 2s
Type "clear"
Enter
Wait

Type "ann ls"
Enter
Wait
Sleep 4s
Type "clear"
Enter
Wait

Type "# Ann's session messages Ben's, end-to-end encrypted"
Enter
Wait
Type "ann send --from-session s-ann --to ben 'Heads up: moving refreshToken() out of token.ts. Hold that file for 20 min?'"
Enter
Wait
Sleep 2s
Type "demo_inbox ben s-ben"
Enter
Wait
Sleep 5s
Type "clear"
Enter
Wait

Type "# What Ann's agent sees before its next edit"
Enter
Wait
Type "demo_conflicts ann api src/auth/token.ts"
Enter
Wait
Sleep 6s
