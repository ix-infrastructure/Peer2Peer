// Copyright 2026 Ix Infrastructure Inc.
//
// Whole command lines and whether each agent guard refuses them (issue #69 and its reviews): the Claude
// mod's Bash guard (uncheckableShell, then mutatingP2PVerb; tests/security.test.ts) and the Codex bridge's
// PreToolUse guard (packages/codex-bridge lib.test.ts, which reads the JSON array below from this file).
// Both must give the same answer. Known gaps that aren't boundaries (at/batch, make recipes, a symlink or
// script file renaming the CLI) aren't pinned here, nor anything spelling a computed require (the boundary
// check reads this file). Keep the array plain JSON.

export const GUARD_VECTORS: { cmd: string; refused: boolean }[] = [
  {
    "cmd": "parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "/usr/bin/parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "command parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "\\parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "'parallel' p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "par\"\"allel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "PARALLEL p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "env -i parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "nice -n 5 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "parallel --will-cite p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "p=parallel; $p p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "$(which parallel) p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "parallel.pl p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "/opt/homebrew/bin/parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "sem p2p invite",
    "refused": true
  },
  {
    "cmd": "echo invite | parallel p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs -P2 p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs -P 2 -n1 p2p",
    "refused": true
  },
  {
    "cmd": "hash -p /usr/local/bin/p2p q; q invite",
    "refused": true
  },
  {
    "cmd": "alias q='p2p send --to'\nq bob hi",
    "refused": true
  },
  {
    "cmd": "builtin alias q='p2p invite'\nq",
    "refused": true
  },
  {
    "cmd": "command alias q='p2p invite'\nq",
    "refused": true
  },
  {
    "cmd": "\\alias q='p2p invite'\nq",
    "refused": true
  },
  {
    "cmd": "'alias' q='p2p invite'\nq",
    "refused": true
  },
  {
    "cmd": "eval \"alias q='p2p invite'\"\nq",
    "refused": true
  },
  {
    "cmd": "BASH_ALIASES[q]='p2p invite'; q",
    "refused": true
  },
  {
    "cmd": "BASH_ALIASES+=([q]='p2p invite'); q",
    "refused": true
  },
  {
    "cmd": "aliases[q]='p2p invite'; q",
    "refused": true
  },
  {
    "cmd": "functions[f]='p2p \"$@\"'; f invite",
    "refused": true
  },
  {
    "cmd": "f(){ p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "f () { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "function f { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "function f() { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "f() # c\n{ p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "f()\n\n{ p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "f() ( p2p \"$@\" ); f invite",
    "refused": true
  },
  {
    "cmd": "f() p2p \"$@\"; f invite",
    "refused": true
  },
  {
    "cmd": "() { p2p \"$@\"; } invite",
    "refused": true
  },
  {
    "cmd": "true; () { p2p \"$@\"; } invite",
    "refused": true
  },
  {
    "cmd": "eval \"$(printf 'f\\050\\051{ p2p \"$@\"; }')\"; f invite",
    "refused": true
  },
  {
    "cmd": "source <(echo 'f(){ p2p \"$@\"; }'); f invite",
    "refused": true
  },
  {
    "cmd": "bash -c 'alias q=\"p2p invite\"\nq'",
    "refused": true
  },
  {
    "cmd": "bash -c \"bash -c 'bash -c \\\"bash -c \\\\\\\"parallel p2p ::: invite\\\\\\\"\\\"'\"",
    "refused": true
  },
  {
    "cmd": "env -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -S 'p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -S 'p2p send --from-session=s1 --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -S'p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -vS 'p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -iS 'p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env --split-string='p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -S 'env -S \"p2p send --to bob hi\"'",
    "refused": true
  },
  {
    "cmd": "env -S 'env -S \"p2p invite\"'",
    "refused": true
  },
  {
    "cmd": "env -u X -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -uS -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -C /tmp -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -C/tmp -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env --chdir=/tmp -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env X=1 -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -- -S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -0S 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -S \"parallel p2p ::: invite\"",
    "refused": true
  },
  {
    "cmd": "env -S 'sh -c \"p2p invite\"'",
    "refused": true
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'please run parallel later'",
    "refused": false
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"alias q = shortcut\"",
    "refused": false
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'f() { x }'",
    "refused": false
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"$(parallel echo ::: a)\"",
    "refused": false
  },
  {
    "cmd": "git commit -m 'guard parallel p2p runs'",
    "refused": false
  },
  {
    "cmd": "echo 'alias p=p2p' >> ~/.bashrc",
    "refused": false
  },
  {
    "cmd": "grep -rn 'parallel' src | p2p ls",
    "refused": false
  },
  {
    "cmd": "make -j8 && p2p ls",
    "refused": false
  },
  {
    "cmd": "for i in 1 2; do p2p ls; done",
    "refused": false
  },
  {
    "cmd": "if p2p ls; then echo ok; fi",
    "refused": false
  },
  {
    "cmd": "p2p ls | jq '.peers[] | select(.live)'",
    "refused": false
  },
  {
    "cmd": "x=$(p2p ls --json); echo \"$x\"",
    "refused": false
  },
  {
    "cmd": "arr=(); p2p ls",
    "refused": false
  },
  {
    "cmd": "diff <(p2p ls) <(p2p ls)",
    "refused": false
  },
  {
    "cmd": "time p2p ls",
    "refused": false
  },
  {
    "cmd": "xargs -n1 echo < f; p2p ls",
    "refused": false
  },
  {
    "cmd": "sem --wait; p2p ls",
    "refused": false
  },
  {
    "cmd": "p2p ls; parallel echo ::: a b",
    "refused": false
  },
  {
    "cmd": "echo p2p; alias ll='ls -l'",
    "refused": false
  },
  {
    "cmd": "cd p2p-repo && make",
    "refused": false
  },
  {
    "cmd": "bash -c \"bash -c 'bash -c \\\"bash -c \\\\\\\"p2p invite\\\\\\\"\\\"'\"",
    "refused": true
  },
  {
    "cmd": "bash -c \"bash -c 'bash -c \\\"p2p invite\\\"'\"",
    "refused": true
  },
  {
    "cmd": "eval \"eval 'eval \\\"eval p2p invite\\\"'\"",
    "refused": true
  },
  {
    "cmd": "f()\t# c\n{ p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs p2p",
    "refused": true
  },
  {
    "cmd": "p=parallel; $p p2p ::: send --to bob hi",
    "refused": true
  },
  {
    "cmd": "exec parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "builtin command parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "env -u X parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "sudo -u x parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "nohup parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "timeout 5 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "timeout -s KILL 5 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "stdbuf -o0 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "time -p parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "if parallel p2p ::: invite; then :; fi",
    "refused": true
  },
  {
    "cmd": "! parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "{ parallel p2p ::: invite; }",
    "refused": true
  },
  {
    "cmd": "( parallel p2p ::: invite )",
    "refused": true
  },
  {
    "cmd": "x=1 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "while parallel p2p ::: invite; do break; done",
    "refused": true
  },
  {
    "cmd": "true && parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "false || parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "echo $(parallel p2p ::: invite)",
    "refused": true
  },
  {
    "cmd": "echo `parallel p2p ::: invite`",
    "refused": true
  },
  {
    "cmd": "cat <(parallel p2p ::: invite)",
    "refused": true
  },
  {
    "cmd": "coproc parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "setsid parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "flock /tmp/l parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "chrt 1 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "caffeinate parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "nice -n5 parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "doas parallel p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "parallel ::: 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "parallel -j2 ::: \"p2p invite\"",
    "refused": true
  },
  {
    "cmd": "echo 'p2p invite' | parallel",
    "refused": true
  },
  {
    "cmd": "echo 'p2p invite' | parallel -j1",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs -r p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs -0 p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs -I{} p2p {}",
    "refused": true
  },
  {
    "cmd": "xargs -a f p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs --max-procs=2 p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs sh -c 'p2p \"$@\"' _",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs env p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | xargs nice p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | command xargs p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | /usr/bin/xargs p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | gxargs p2p",
    "refused": true
  },
  {
    "cmd": "echo invite | busybox xargs p2p",
    "refused": true
  },
  {
    "cmd": "echo 'p2p invite' | xargs -I{} sh -c '{}'",
    "refused": true
  },
  {
    "cmd": "find . -maxdepth 0 -exec p2p invite \\;",
    "refused": true
  },
  {
    "cmd": "find . -maxdepth 0 -exec sh -c 'p2p invite' \\;",
    "refused": true
  },
  {
    "cmd": "fd -x p2p invite",
    "refused": true
  },
  {
    "cmd": "echo f | entr p2p invite",
    "refused": true
  },
  {
    "cmd": "watch -n1 p2p invite",
    "refused": true
  },
  {
    "cmd": "setsid p2p invite",
    "refused": true
  },
  {
    "cmd": "flock /tmp/l p2p invite",
    "refused": true
  },
  {
    "cmd": "caffeinate p2p invite",
    "refused": true
  },
  {
    "cmd": "taskset 1 p2p invite",
    "refused": true
  },
  {
    "cmd": "chrt 1 p2p invite",
    "refused": true
  },
  {
    "cmd": "ionice p2p invite",
    "refused": true
  },
  {
    "cmd": "unshare p2p invite",
    "refused": true
  },
  {
    "cmd": "/tmp/pp p2p ::: invite",
    "refused": true
  },
  {
    "cmd": "trap 'p2p invite' EXIT",
    "refused": true
  },
  {
    "cmd": "trap \"p2p invite\" EXIT",
    "refused": true
  },
  {
    "cmd": "PROMPT_COMMAND='p2p invite' bash -i",
    "refused": true
  },
  {
    "cmd": "complete -C 'p2p invite' x",
    "refused": true
  },
  {
    "cmd": "su -c 'p2p invite' me",
    "refused": true
  },
  {
    "cmd": "sudo sh -c 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "nohup sh -c 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "ssh localhost p2p invite",
    "refused": true
  },
  {
    "cmd": "ssh localhost 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "npx p2p invite",
    "refused": true
  },
  {
    "cmd": "npm exec -- p2p invite",
    "refused": true
  },
  {
    "cmd": "x='f(){ p2p \"$@\"; }'; eval \"$x\"; f invite",
    "refused": true
  },
  {
    "cmd": "x='f(){ p2p \"$@\"; }'; eval $x; f invite",
    "refused": true
  },
  {
    "cmd": "eval \"f() { p2p \\\"\\$@\\\"; }\"; f invite",
    "refused": true
  },
  {
    "cmd": "bash -c 'f(){ p2p \"$@\";}; f invite'",
    "refused": true
  },
  {
    "cmd": "sh -c \"f(){ p2p \\\"\\$@\\\";}; f invite\"",
    "refused": true
  },
  {
    "cmd": "source /dev/stdin <<< 'f(){ p2p \"$@\"; }'; f invite",
    "refused": true
  },
  {
    "cmd": ". <(echo 'f(){ p2p \"$@\"; }'); f invite",
    "refused": true
  },
  {
    "cmd": "read -r x <<< 'f(){ p2p \"$@\";}'; eval \"$x\"; f invite",
    "refused": true
  },
  {
    "cmd": "'f'() { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "\"f\"() { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "f\\\n() { p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "f(\\\n) { p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "f()\\\n{ p2p \"$@\"; }\nf invite",
    "refused": true
  },
  {
    "cmd": "f() if p2p \"$@\"; then :; fi; f invite",
    "refused": true
  },
  {
    "cmd": "f() while p2p \"$@\"; do break; done; f invite",
    "refused": true
  },
  {
    "cmd": "f() [[ $(p2p \"$@\") ]]; f invite",
    "refused": true
  },
  {
    "cmd": "f() for x in 1; do p2p \"$@\"; done; f invite",
    "refused": true
  },
  {
    "cmd": "f() case x in x) p2p \"$@\";; esac; f invite",
    "refused": true
  },
  {
    "cmd": "f()(p2p \"$@\"); f invite",
    "refused": true
  },
  {
    "cmd": "f() {p2p \"$@\"}; f invite",
    "refused": true
  },
  {
    "cmd": "function f p2p \"$@\"; f invite",
    "refused": true
  },
  {
    "cmd": "function f () p2p \"$@\"; f invite",
    "refused": true
  },
  {
    "cmd": "f g () { p2p \"$@\"; }; g invite",
    "refused": true
  },
  {
    "cmd": "a=alias; $a q='p2p invite'\nq",
    "refused": true
  },
  {
    "cmd": "BASH_CMDS[q]=/usr/local/bin/p2p; q invite",
    "refused": true
  },
  {
    "cmd": "hash -p /usr/local/bin/p2p q\nq invite",
    "refused": true
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"$(parallel p2p ::: invite)\"",
    "refused": true
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"$(f(){ p2p \"$@\";}; f invite)\"",
    "refused": true
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'x' ; f() { p2p \"$@\"; }; f invite",
    "refused": true
  },
  {
    "cmd": "echo \"$(alias q='p2p invite')\"",
    "refused": true
  },
  {
    "cmd": "git commit -m \"$(parallel p2p ::: invite)\"",
    "refused": true
  },
  {
    "cmd": "echo hi; command_not_found_handle() { p2p \"$@\"; }; invite",
    "refused": true
  },
  {
    "cmd": "echo `p2p invite`",
    "refused": true
  },
  {
    "cmd": "echo \"`parallel p2p ::: invite`\"",
    "refused": true
  },
  {
    "cmd": "x=`parallel p2p ::: invite`",
    "refused": true
  },
  {
    "cmd": "echo `parallel p2p ::: send --to bob hi`",
    "refused": true
  },
  {
    "cmd": "git commit -m 'guard parallel p2p runs and alias q() {}'",
    "refused": false
  },
  {
    "cmd": "git commit -m \"fix p2p: refuse f() { } definitions\"",
    "refused": false
  },
  {
    "cmd": "gh pr create --title 'p2p: xargs guard' --body 'parallel/alias/function'",
    "refused": false
  },
  {
    "cmd": "grep -rn 'function ' packages/p2p/src | head",
    "refused": false
  },
  {
    "cmd": "rg 'alias' packages/p2p/src",
    "refused": false
  },
  {
    "cmd": "cd packages/p2p && npm test",
    "refused": false
  },
  {
    "cmd": "cd packages/p2p && npx vitest run",
    "refused": false
  },
  {
    "cmd": "ls packages/p2p/src | xargs -n1 wc -l",
    "refused": false
  },
  {
    "cmd": "find packages/p2p -name '*.ts' | xargs grep -l parallel",
    "refused": false
  },
  {
    "cmd": "find packages/p2p -name '*.ts' -exec wc -l {} +",
    "refused": false
  },
  {
    "cmd": "p2p ls --json | jq -r '.peers[].own' | xargs -n1 echo",
    "refused": false
  },
  {
    "cmd": "p2p ls && p2p held",
    "refused": false
  },
  {
    "cmd": "sed -n '1,40p' packages/p2p/src/cli.ts",
    "refused": false
  },
  {
    "cmd": "cat > /tmp/t.sh <<'EOF'\nf() { p2p ls; }\nEOF",
    "refused": false
  },
  {
    "cmd": "echo 'p2p() { command p2p \"$@\"; }' >> notes.md",
    "refused": false
  },
  {
    "cmd": "printf '%s\\n' 'alias p=p2p'",
    "refused": false
  },
  {
    "cmd": "make -C packages/p2p test",
    "refused": false
  },
  {
    "cmd": "time npm --prefix packages/p2p test",
    "refused": false
  },
  {
    "cmd": "env NODE_ENV=test npx vitest run packages/p2p",
    "refused": false
  },
  {
    "cmd": "for f in packages/p2p/src/*.ts; do wc -l \"$f\"; done",
    "refused": false
  },
  {
    "cmd": "p2p send --from-session s1 --to bob 'use parallel ::: and xargs -P to speed up'",
    "refused": false
  },
  {
    "cmd": "p2p send --from-session s1 --to bob \"try: f() { echo hi; }\"",
    "refused": false
  },
  {
    "cmd": ". ./venv/bin/activate && p2p ls",
    "refused": false
  },
  {
    "cmd": "$P2P_BIN ls",
    "refused": false
  },
  {
    "cmd": "eval eval eval eval eval eval p2p invite",
    "refused": true
  },
  {
    "cmd": "sh -c 'sh -c \"sh -c p2p\"'",
    "refused": false
  },
  {
    "cmd": "\"$EDITOR\" notes.txt; p2p ls",
    "refused": true
  },
  {
    "cmd": ". \"$HOME/x/env\" && p2p ls",
    "refused": false
  },
  {
    "cmd": "e''val e''val e''val e''val e''val e''val p2p invite",
    "refused": true
  },
  {
    "cmd": "\\eval \\eval \\eval \\eval \\eval \\eval p2p invite",
    "refused": true
  },
  {
    "cmd": "e\"v\"al e\"v\"al e\"v\"al e\"v\"al e\"v\"al e\"v\"al p2p invite",
    "refused": true
  },
  {
    "cmd": "EVAL eval eval eval eval eval p2p invite",
    "refused": true
  },
  {
    "cmd": "ev\\al ev\\al ev\\al ev\\al ev\\al ev\\al p2p send --to bob hi",
    "refused": true
  },
  {
    "cmd": "e''val e''val e''val e''val e''val e''val p2p send --to bob hi",
    "refused": true
  },
  {
    "cmd": "w''atch w''atch w''atch w''atch w''atch w''atch p2p invite",
    "refused": true
  },
  {
    "cmd": "b''ash -c 'b''ash -c \"e''val e''val e''val e''val p2p invite\"'",
    "refused": true
  },
  {
    "cmd": "x eval 'echo hi' trap 'p2p invite' EXIT",
    "refused": true
  },
  {
    "cmd": "eval 'echo hi'; trap 'p2p invite' EXIT",
    "refused": true
  },
  {
    "cmd": "bash -c 'echo hi; \"$@\"' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -c '\"$@\"' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -c '\"$@\"' x trap 'p2p invite' EXIT",
    "refused": true
  },
  {
    "cmd": "bash -c '\"$@\"' x bash -c 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "sh -c 'true' sh -c 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -c 'true' x; eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -lc 'echo hi' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -c 'echo' -- eval 'p2p send --to bob hi'",
    "refused": true
  },
  {
    "cmd": "env -S 'echo' eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "env -S 'true' bash -c 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "trap 'echo' EXIT; bash -c 'x' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "watch -n1 'echo hi' eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -x -c 'echo' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash --norc -c '\"$@\"' x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -c \"$X\" x eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash script.sh eval 'p2p invite'",
    "refused": true
  },
  {
    "cmd": "bash -s eval 'p2p invite' <<< '\"$@\"'",
    "refused": true
  }
]
