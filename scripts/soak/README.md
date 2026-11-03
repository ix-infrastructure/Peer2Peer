# Soak and chaos test

`soak.mjs` runs several simulated users against two local relays for minutes to hours, through the real `p2p` binary, under a seeded random workload and seeded chaos, and checks invariants the whole time. It goes past the unit and integration tests: many processes per home at once, long-running `p2p watch` children that get paused and killed, relays that die mid-run, links with latency and jitter.

Nothing here reads your `~/.p2p` or talks to a real relay. Every home, `HOME` and relay database is in a temporary directory, both relays listen on 127.0.0.1, and every child gets an environment built from scratch (only `PATH` is inherited).

```sh
# build first, in this order: core, relay, codex-bridge, p2p, ext-ix
cd packages/p2p
npm run soak -- --quick --seed 7          # quick mode: about 3-5 minutes
npm run soak -- --minutes 30 --seed 7     # a 30-minute run (10-minute epochs)
npm run soak -- --minutes 90 --users 5    # the long mode: 60+ minutes, five users
```

On a laptop, keep the machine awake for long runs (`caffeinate -i npm run soak -- ...` on macOS): when the host sleeps, every process stops at once and the timers run late. The harness notices (a `host-stall` in the timeline) and excuses commands that spanned one, but the checks after it are weaker.

Options: `--quick`, `--minutes N` (workload time; quick: 2, otherwise 30), `--seed S` (random when omitted, and printed), `--users 3..10` (quick: 3, otherwise 4; past 5, one machine runs 20+ clients and their watches, so expect contention), `--epoch-minutes M` (heal and check every M minutes; quick: once at the end, otherwise 10), `--heal-timeout S` (how long a check waits for convergence after healing; quick: 90, otherwise 150), `--max-rtt MS` (150), `--concurrency N` (operations in flight, 6), `--no-chaos`, `--bin dist|bundle|PATH` (`packages/p2p/dist`, the bundled CLI the Claude mod ships, or another build of it, for a before/after comparison), `--out FILE` (the JSON report; by default in `$TMPDIR/p2p-soak-reports/`), `--keep` (keep the scratch directory, to look at the homes afterwards).

Tail-latency diagnostics (off by default; they slow the run a little):
- `--trace-slow MS`: every command and watch runs with `P2P_DEBUG=1`. Commands slower than MS are kept in the report's `slow` list with their step log, each line stamped with its arrival time (ms since spawn); the watches' step logs go to `<report>.traces/`, stamped with wall-clock ms. Under `P2P_DEBUG` the CLI also logs store-lock waits and hold times (`lock cli|v3: waited …, held …`, and `still waiting … (held by pid …)` every second) and its in-process state queue. The report's `harnessLag` lists seconds when the harness's own event loop (which runs the links' proxies) lagged 100 ms or more.
- `--cpu-prof DIR`: every command runs with `--cpu-prof`; the profiles of commands slower than `--trace-slow` (or all, without it) are kept in DIR as `<dev>-<op>-<ms>ms-<n>.cpuprofile`, with the relays' (written when they stop cleanly).

The exit code is 0 when every invariant held.

## What runs

**Users and topology.** 3 to 10 users. Each has two devices: the first is key-holding (`p2p init`), the second is linked to it (§2.4, through the library: the CLI's `link start` confirms a compare code a script can't know in advance). Everyone is friends with everyone, and everyone is in one open circle, owned by the first user, which is everyone's default circle. Each first device runs a circle session (`fp`, the one that publishes footprints) and a private session shared with every friend (`dm`); each second device runs a circle session (`c2`). Every session has its own long-running `p2p watch --session <sid> --jsonl`, as the Claude Code mod runs it.

**Links.** Each device reaches each relay through its own TCP proxy (`packages/p2p/bench/proxy.mjs`, shared with the latency bench), with a seeded RTT of 0 to 150 ms and up to 30 ms of jitter (chunks are delayed, never reordered).

**Relays.** Two `packages/relay` processes with SQLite on disk, so a SIGKILL and restart keeps what they stored. Loopback is one source IP for every simulated user, so the per-IP limits are lifted; the per-identity ones are the defaults. The mailbox quota is lowered (150 envelopes in quick mode, 400 otherwise) so the run can fill one.

**Workload** (seeded): statuses with 0 to 3 subagents (`--agents-json`, `--cap agents.v1`), at least every 45 s per live session; messages into live sessions the sender may see per the model (direct sessions between friends, circle sessions between members); Ix footprints from the fake `ix` (`packages/ext-ix/scripts/fake-ix.cjs`, shared with ext-ix's tests) over one fake repository that every user has cloned (six files, two functions each; editing the first function of file k is in ring 1 of file k+1's second function), deliberately overlapping someone's current edit more often than not; `p2p ls` and `p2p friends`; unfriend and re-invite (at most every 2 minutes in long runs); leave the circle and join again (at most every 4 minutes; a former member's join is held, and the owner approves it with `p2p held approve`); sessions that start and end; identity document refreshes (`p2p profile set`, `p2p identity republish`).

**Chaos** (seeded, every kind at least once per epoch, retried when nothing is eligible):

| kind | what |
|---|---|
| relay kill | SIGKILL one relay, restart it 5-60 s later on the same port and database |
| pause | SIGSTOP every process of one device for 30-120 s (laptop sleep); nothing new starts on it meanwhile |
| drop | destroy one device's connections, or everyone's |
| skew | one device's clock runs 90 s ahead or behind from the start of the workload (faults.mjs shifts `Date` and the start times `ps` reports) |
| mailbox fill | while a device sleeps, a friend sends its mailbox 70% of the relay's quota (through the library); every one must arrive once it wakes |
| malformed | a friend sends a status whose state isn't busy or idle, and a message whose text is a number (through the library) |
| poison | a message whose application fails every time on its recipients (faults.mjs fails the write with ENOSPC) |
| crash mid-apply | a message whose first application on each recipient device kills that process with SIGKILL (faults.mjs); the harness restarts its watch, as the mod would |

**Heal and check.** At the end of each epoch, chaos stops: paused devices resume, relays come back, friendships and the circle are restored, watches are restarted. Then every device drains (`p2p ls --all`) until everything converged, or the heal timeout ran out.

## Invariants

Checked continuously (duplicates, crashes and hangs, names, memory, disk) and at every heal:

| invariant | |
|---|---|
| delivery-exactly-once | every message `p2p send` reported delivered to a session the model says it may reach is applied on the target device (its event log), once, within the heal timeout. A message whose pair had an unfriend or re-friend (or, for a circle session, a circle leave or re-join) while it was in flight is "racy": counted, not held to this |
| no-duplicates | no message applied twice on a device; no watch line printed twice, except a line re-printed by the next watch after one was killed (its cursor lags a line) |
| status-convergence | every viewer device's `p2p ls --all` shows every session's latest status delivered to it (latest by envelope ts, as receivers keep it), and its agents |
| footprint-overlap | after one more publish each, `p2p ix overlaps --json` shows exactly the expected tiers between every pair of footprint sessions that see each other: same-symbol (high), depends in the right direction (medium), same-file (medium); none for a pair that doesn't overlap |
| hashed-names | no symbol name of the fake repository appears in a user's home unless that user's own footprint held it; overlap lines never name a symbol, never carry `detail`, and name a file only when it is the user's own status file |
| poison-gave-up | the poison message is never applied; the recipient's given-up count rises, and `p2p doctor` reports it without its content |
| malformed-rejected | the malformed envelopes are rejected (never stored, never applied) without crashing anything |
| crash-mid-apply | the fault fired, and the message was applied once afterwards |
| doctor | on every device, with its watches stopped, `p2p doctor` changes no file in P2P_HOME, and has no ✗ (the skewed device's clock check excepted: its clock is still off) |
| resources | peak RSS of relays (400 MB) and watches (300 MB); P2P_HOME at most 32 MB and not still growing in the last third of a long run; at most 3 leftover temp files |
| latency | p50 and p95 per operation, over calm samples (no chaos on that device or relay in the last 10-15 s, not during a check, not during setup), within 2.5× (p50) and 4× (p95) of the bench README's "after" numbers at RTT 80 ms, given at least 20 samples. Setup runs its steps for every device at once (every session's first status, every device's `circle ls` and `ls`), a synchronized burst on one machine's disk that no real user produces: it is reported on its own line (`setup burst`) and in the report's `latency.<op>.setup`, not held to the budget |
| no-crashes | no unhandled exception or stack trace on any stderr, no exit by a signal the harness didn't send, no command over its timeout, no relay error |
| no-orphans | after shutdown, no relay connection open and no process left that names the scratch directory |

## The report

A summary table on stdout and a JSON report: per invariant, pass or fail with the failures; message, status and footprint counts; every chaos step; latency per operation (calm and all samples, the setup burst apart, and every sample as `[t, ms, calm, setup]` under `samples`); peak RSS, P2P_HOME and relay database sizes; and the full timeline of operations and chaos steps. A failing run prints the seed and the command to run it again. The seed fixes the plan (users, links, which operations and chaos in which order); real timing still varies, so a failure that depends on a race may need a few runs, or the timeline, to reproduce.

## Results

Runs on 2026-10-25 (Apple-silicon Mac, Node 26.5, `--bin dist`) are summarised in the pull request that added this harness, with the bugs they found. The tail-latency work that followed (`ls` and `status` p95 at five users, and what caused it) is in [`packages/p2p/bench/README.md`](../../packages/p2p/bench/README.md#tail-latency-under-load-the-64-soak), with before/after numbers for 3, 5 and 10 users.
