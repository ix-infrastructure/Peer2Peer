# Latency benchmark

`latency.mjs` measures how long Peer2Peer takes end to end, on this machine, against a local relay. It makes two or more throwaway identities (temporary `P2P_HOME`s and `HOME`, never `~/.p2p`) on an in-process relay from `packages/relay` with its SQLite store in a temporary directory. The relay is reached through a TCP proxy that holds every chunk for RTT/2 in each direction, including the TCP handshake, so the same run gives loopback numbers and numbers for a simulated link. Real users are on a private network or the internet. Nothing talks to a real relay.

```sh
# after building core, relay, codex-bridge and p2p (in that order)
cd packages/p2p
npm run bench:latency                         # 15 iterations, RTT 0 and 80 ms
node bench/latency.mjs --iters 5 --only c,e   # a quick look at the send paths
node bench/latency.mjs --trace --only c       # the last run's P2P_DEBUG step log, with arrival times
```

Options: `--iters N`, `--rtt MS` (the simulated round trip, beside loopback), `--peers 1,50,200` (scenario f), `--friends N` (the status fan-out in d2), `--bin bundle|dist` (by default the bundled `mods/claude/peer2peer/bin/p2p.mjs`, which is what users run), `--json FILE`, `--only a,b,...`, `--trace`.

## What it measures

Each scenario reports p50 and p95. Each CLI command is also split into stages from its `P2P_DEBUG=1` step log: `connect` (WebSocket and device auth), `drain` (receiving what was queued), `request` (relay round trips, summed when they run in parallel), `docRefresh` and `fetch` (identity documents over HTTP), and `other`, which is everything else: node boot, module load, keys and state on disk, crypto, and closing.

| | scenario |
|---|---|
| a | cold `p2p` startup: `node -e 0`, then `p2p --version` (module load), then `p2p whoami` (keys and state), and the same with the ext-ix extension enabled |
| b | relay connect: TCP, WebSocket upgrade and `hello`; then device auth (`RelayConnection.open`) |
| c | `p2p send`, from spawn until the message line appears in the recipient's `watch --jsonl` (the watch is driven by the mod's own `watchLoop`) |
| d | `p2p status`, until it reaches the peer's watch, and until the peer's next `ls` shows it |
| d2 | `p2p status` to a session shared with seven friends (the fan-out) |
| e | the Claude mod path: `backend.ts` `P2P.send` (what SendMessage runs) until the `<cross-session-message>` is framed for the recipient session, as the mod's integration test drives it. A busy session reads it at its next tool round. An idle one first gathers for `DELIVER_DEBOUNCE_MS` (500 ms), which is added as a constant |
| f | `p2p ls --json` with N peer sessions held |
| g | an identity document refresh (`refreshIdentity`, forced): the HTTP tips fetch, and verifying the held chain cold and again in the same process |

## Baseline and results

Measured on 2026-10-22 on an Apple-silicon Mac (macOS, Node 26.5, 15 iterations each), with the bundled CLI. "Before" is `main` at 9d10240, "after" is this branch. Numbers are milliseconds, p50 / p95. On another machine, run the script on both commits rather than comparing against these.

| scenario | metric | RTT | before p50 / p95 | after p50 / p95 |
|---|---|---:|---:|---:|
| a cold startup | node -e 0 (node boot) | 0 | 37 / 40 | 36 / 56 |
| a cold startup | p2p --version (+ module load) | 0 | 67 / 69 | 64 / 68 |
| a cold startup | p2p whoami --json (+ keys, state) | 0 | 98 / 102 | 93 / 102 |
| a cold startup | p2p whoami --json, ext-ix enabled | 0 | 100 / 106 | 98 / 105 |
| b relay connect | TCP + WS upgrade + hello | 0 | 2 / 4 | 2 / 4 |
| b relay connect | + device auth (RelayConnection.open) | 0 | 3 / 16 | 3 / 16 |
| b relay connect | TCP + WS upgrade + hello | 80 | 164 / 165 | 164 / 166 |
| b relay connect | + device auth (RelayConnection.open) | 80 | 249 / 254 | 246 / 249 |
| c send → watch | p2p send → line in recipient's watch | 0 | 912 / 922 | 167 / 219 |
| c send → watch | p2p send process (spawn → exit) | 0 | 584 / 726 | 147 / 195 |
| c send → watch | relay 'sent' → watch line (delivery + watch poll) | 0 | 346 / 367 | 35 / 39 |
| c send → watch | p2p send → line in recipient's watch | 80 | 1210 / 1505 | 502 / 544 |
| c send → watch | p2p send process (spawn → exit) | 80 | 1012 / 1297 | 483 / 521 |
| c send → watch | relay 'sent' → watch line (delivery + watch poll) | 80 | 316 / 363 | 38 / 48 |
| d status → peer | p2p status → peer's watch | 0 | 1226 / 1593 | 275 / 336 |
| d status → peer | p2p status → peer's ls (status, then ls) | 0 | 1801 / 2118 | 387 / 537 |
| d status → peer | p2p status process | 0 | 853 / 1070 | 246 / 308 |
| d status → peer | p2p ls process | 0 | 529 / 603 | 114 / 201 |
| d status → peer | p2p status → peer's watch | 80 | 1551 / 1560 | 610 / 680 |
| d status → peer | p2p status → peer's ls (status, then ls) | 80 | 2414 / 2431 | 981 / 1047 |
| d status → peer | p2p status process | 80 | 1259 / 1282 | 578 / 648 |
| d status → peer | p2p ls process | 80 | 864 / 883 | 368 / 386 |
| d2 status fan-out | p2p status to 7 friends (process) | 0 | 1182 / 1524 | 347 / 601 |
| d2 status fan-out | p2p status to 7 friends (process) | 80 | 1899 / 2766 | 663 / 864 |
| e mod SendMessage → <cross-session-message> | busy recipient (next tool round) | 0 | 906 / 1199 | 169 / 214 |
| e mod SendMessage → <cross-session-message> | idle recipient (+ 500 ms gather, DELIVER_DEBOUNCE_MS) | 0 | 1406 / 1699 | 669 / 714 |
| e mod SendMessage → <cross-session-message> | SendMessage tool call (P2P.send) returns | 0 | 615 / 825 | 148 / 193 |
| e mod SendMessage → <cross-session-message> | busy recipient (next tool round) | 80 | 1206 / 1228 | 602 / 765 |
| e mod SendMessage → <cross-session-message> | idle recipient (+ 500 ms gather, DELIVER_DEBOUNCE_MS) | 80 | 1706 / 1728 | 1102 / 1265 |
| e mod SendMessage → <cross-session-message> | SendMessage tool call (P2P.send) returns | 80 | 981 / 1148 | 531 / 661 |
| g identity doc refresh | refreshIdentity (force) | 0 | 91 / 124 | 34 / 59 |
| g identity doc refresh | HTTP tips fetch alone | 0 | 2 / 2 | 2 / 2 |
| g identity doc refresh | verify held chain alone (cold process) | 0 | 2 / 2 | 2 / 2 |
| g identity doc refresh | verify held chain again (same process) | 0 | 2 / 2 | 0 / 0 |
| g identity doc refresh | refreshIdentity (force) | 80 | 122 / 205 | 252 / 373 |
| g identity doc refresh | HTTP tips fetch alone | 80 | 84 / 85 | 83 / 84 |
| g identity doc refresh | verify held chain alone (cold process) | 80 | 2 / 2 | 2 / 2 |
| g identity doc refresh | verify held chain again (same process) | 80 | 2 / 2 | 0 / 0 |
| f ls (N=1) | p2p ls --json, 1 peer sessions | 0 | 529 / 552 | 118 / 131 |
| f ls (N=1) | p2p ls --json, 1 peer sessions | 80 | 866 / 898 | 362 / 368 |
| f ls (N=50) | p2p ls --json, 50 peer sessions | 0 | 550 / 560 | 130 / 141 |
| f ls (N=50) | p2p ls --json, 50 peer sessions | 80 | 876 / 890 | 377 / 383 |
| f ls (N=200) | p2p ls --json, 200 peer sessions | 0 | 579 / 612 | 157 / 163 |
| f ls (N=200) | p2p ls --json, 200 peer sessions | 80 | 905 / 928 | 401 / 419 |

The forced refresh row at RTT 80 (g) moved between runs from about 120 ms to 250 ms on the same code: isolated reruns give 119 / 141 after and 122 / 150 before. Nothing in this change touches that path.

## Where the time went, and what changed

Before, every short command waited out a 400 ms quiet period for queued envelopes, even with nothing queued. A watch spent about 110 ms of curve work per received message re-verifying the same certificates, and then printed the message at its next 300 ms poll. Closing cost one more round trip.

1. **`caught-up` (protocol §5.4).** After the backlog, a relay sends `{"t":"caught-up"}` once per connection. The drain right after connecting ends there, once everything delivered has been handled, instead of after 400 ms of quiet. A relay from before this change is waited out as before. Commands that wait for answers to arrive live (circle joins) keep the quiet period.
2. **Verification memo (core `crypto.ts`).** Successful Ed25519 verifications are remembered by SHA-256(key ‖ signature ‖ message), and strong-key checks by the key bytes. The memo is bounded and keeps successes only. Time, revocation, allowlist and chain rules are still checked on every call. Verifying a received message dropped from about 110 ms to under 10 ms after the first.
3. **Push in `watch`.** The watch wakes as soon as this process appends to the event log, or when the log file changes (another `p2p` process). The 300 ms poll stays as a backstop.
4. **Closing.** This branch first closed the socket without waiting for the relay's closing frame, which saved one round trip per command. Review L1 put it back to safe: a command waits for the closing frame, at most 1 s (instead of ws's 30 s), so a late RST can't throw away acks the relay hasn't read yet. Per-command times at RTT 80 include that round trip again (about +80 ms on the process time). The recipient side is unaffected.
5. **Status fan-out in parallel.** Up to 8 recipients at once, and each recipient's devices together, with one seq block per recipient. An in-process queue in front of the state lock replaces polling the lock file. Repeat certificate-cache writes are skipped (`putDeviceCert` with the same certificate).

What remains at RTT 80 is mostly the relay connect: three round trips (TCP, WebSocket upgrade and `hello`, auth), plus one more for TLS on `wss`. Then about 100 ms of node boot, module load and key loading, and one round trip per request.

Review fixes on the same branch (correctness, not latency):
- **M1.** While a command closes, envelope handlers still running keep using the closing pool. A handler that outlives the close may not open a new pool, which used to take, and then lose, the next command's deliveries.
- **M2.** The replay window records an envelope only after its effects are written. Verification claims the envelope (core `claimReplay`), and the receiver commits it after applying it. A concurrent copy gets `replay-in-progress` and is not acked. A claim whose holder died is taken over, so a crash before applying no longer loses the message.
- **Re-review M-1, L-1, L-2.** A claim held on the same machine is judged by liveness only, never by age; another host's claim falls back to a 2-minute TTL. A non-protocol failure, whether in verification or in applying the envelope (I/O, lock, network, the command closing), releases the claim unrecorded and doesn't ack, so the redelivery is applied. Only a protocol rejection spends the seq. A commit that lost a race to another host is logged.
- **Final check M-A and L-C.** Retrying is the exception. Only transient failures are retried: the `closing` refusal, a lock timeout, ENOSPC, EBUSY, EAGAIN, EMFILE, ENFILE and EDQUOT, and transient network failures (ECONNRESET, ETIMEDOUT, ECONNREFUSED, EHOSTUNREACH, ENETUNREACH, EAI_AGAIN, a closed socket, an unreachable relay, a timeout), so a short Wi-Fi drop doesn't lose a friend's accept. The accept path's cap grant now fails the attempt on such an error instead of swallowing it. Deterministic errors are final on the first failure. Every claim counts as an attempt; after 3 the envelope is recorded as given up, then acked and dropped. That is logged as `gave-up` and shown as a count, with no content, in `p2p doctor`. Each envelope gets 8 s (`P2P_ENVELOPE_TIMEOUT_MS`) before the command goes on without it, so a slow one can't eat a short command's drain. Claims also store the holder's process start time, so a reused pid isn't taken for the holder.
- **L3.** The in-process state queue leaves other processes a 60 ms gap after 8 back-to-back updates.

## Regression guard

`src/__tests__/latency.test.ts` pins the mechanisms with generous bounds:
- with a 6 s drain quiet period, `ls` and `friends` still return in under 3 s, having handled what was queued;
- with a 60 s poll, `watch` prints an event appended by its own process or by another one within about 2 s;
- a handler running during close uses the closing pool and opens none (M1);
- an envelope whose handling died before it was applied is applied, once, on redelivery (M2), and so is one whose handling hit a non-protocol error (L-2);
- a burst of state updates leaves another process's update a turn (L3);
- a lock error is retried and applied, a TypeError is final at once, and a poison envelope is acked after 3 attempts and counted in `p2p doctor` (M-A);
- the backlog drain ends with the backlog, while an envelope that arrived live after `caught-up` is still being handled (tail latency, below).

The tail-latency fixes have their own tests: a store lock never exists empty, with or without hard links, and an empty one left by an older client is still judged by the 30 s rule (core `truststore.test.ts`), and a copy whose claim a live process holds waits without taking the lock (core `v3/__tests__/incoming.test.ts`).

## Tail latency under load (the pre-release soak)

The soak harness (`scripts/soak`, `npm run soak`) runs several users, each with two devices, a long-running `p2p watch` per session and seeded chaos, all on one machine. Its quick runs showed `ls` and `status` with a calm p95 of 5-10 s at five users (seed 6; `ls` at 9.9 s with seed 9), while p50 stayed under 1.2 s.

How it was found: `--trace-slow` (every command's `P2P_DEBUG` step log with arrival times, plus lock waits and hold times, which `P2P_DEBUG` now logs for both stores), `--cpu-prof` (the slow commands' and the relays' profiles) and the watches' step logs. The slow commands were idle in their CPU profiles (they were waiting), and so were the relays.

### Root causes

1. **An empty store lock held every process of a home for 30 s.** `FileDocBackend` created `.lock` and then wrote its body. A process that exited in between (a command's 1.5 s exit while an envelope handler was still going) left an empty lock, which other processes may only break as stale after 30 s. Every `p2p` of that home (the watches and every command) waited: lock waits of 10 s and more (`still waiting … held by pid ?`), envelope handlers over their 8 s budget, and after three lock timeouts a legitimate status was given up and dropped. This was the 7-20 s `ls` and `status` tails. Fix (core): the lock body is written to a temp file and hard-linked into place, so a lock is never empty (without hard links it is copied into place exclusively). An empty lock from an older client is still broken only after 30 s: a shorter rule could break a live, stalled creator's lock (pre-release review M-B).
2. **`ps` under the trust store's lock.** On macOS, checking whether another process's replay claim is still alive spawns `ps` (30-100 ms, synchronously), inside `claimReplay`, under the lock. A watch and a short command racing for the same envelopes did it for every envelope, and every other process of the home waited. Fix: answers are cached per pid for 5 s, and a copy whose claim a live process holds now finds out from a lock-free read of the stored claims (`claimHeldElsewhere`) without queueing for the lock at all; only `claimReplay` takes or takes over a claim.
3. **The backlog drain waited for live traffic.** A short command's first drain ended when every relay had said `caught-up` *and* nothing was being handled. In a burst, envelopes kept arriving after `caught-up`, so the queue never emptied and the drain ran to its 5 s cap. It now ends once the envelopes delivered before `caught-up` are handled; later ones are handled as they come.
4. **Locked writes that changed nothing.** Every write is an fsync (about 25-30 ms on this Mac, more under load) under a lock that every process of the home queues for, polling every 50 ms. An identity refresh that found nothing new still rewrote the chain, re-marked it refreshed and took the lock to delete a provisional entry that wasn't there; every envelope took the lock to store the sender's certificate again. These are now checked without the lock first, and skipped when there's nothing to write (a refresh mark or `fetched` time less than 10 s / 5 s old is left as it is, which can only make the next refresh come sooner).

Not the cause: the relays (idle in their profiles during the slow commands), the harness's proxies (its event loop never lagged 100 ms during them), the per-envelope 8 s budget (it only fired behind the empty lock), and `ls`'s work per peer and session (milliseconds).

### Before and after

Quick runs (`npm run soak -- --quick --seed S --users N`), Apple-silicon Mac (14 cores), Node 26.5. "Before" is `main` at 878d2df (its committed bundle, `--bin <path>`), "after" this branch's bundle, both with this branch's harness. Milliseconds, p50 / p95 (max) over the pooled samples of the runs listed.

The setup phase starts every session's first status and every device's `ls` and `circle ls` at the same moment: a synchronized burst on one disk that no real user makes. The earlier soak counted it as calm; this harness reports it apart. Both views are below.

Calm, as the earlier soak counted it (setup included):

| users (runs) | op | before | after |
|---|---|---:|---:|
| 5 (seeds 6, 9) | `ls` | 707 / 7684 (20218) | 692 / 867 (892) |
| 5 (seeds 6, 9) | `status` | 1170 / 7253 (14624) | 1206 / 7662 (8165) |
| 5 (seeds 6, 9) | `circle ls` | 1005 / 13915 (16417) | 1024 / 7509 (8422) |
| 3 (seeds 6, 9) | `ls` | 669 / 807 (839) | 670 / 880 (913) |
| 3 (seeds 6, 9) | `status` | 911 / 2212 (3222) | 956 / 2065 (15175) |
| 10 (seed 6) | `ls` | 969 / 4187 (4316) | 971 / 6247 (6609) |
| 10 (seed 6) | `status` | 2249 / 21372 (25057) | 2669 / 19669 (27959) |

Calm, without the setup burst:

| users (runs) | op | before | after |
|---|---|---:|---:|
| 5 (seeds 6, 9) | `ls` | 679 / 846 (1122) | 713 / 891 (892) |
| 5 (seeds 6, 9) | `status` | 1110 / 2154 (14624) | 1159 / 2164 (2832) |
| 5 (seeds 6, 9) | `send` | 826 / 1349 (2533) | 860 / 1489 (1959) |
| 3 (seeds 6, 9) | `ls` | 667 / 778 (807) | 669 / 906 (913) |
| 3 (seeds 6, 9) | `status` | 860 / 1169 (1886) | 946 / 1296 (15175) |
| 10 (seed 6) | `ls` | 741 / 832 (832) | 664 / 756 (756) |
| 10 (seed 6) | `status` | 2043 / 3679 (20327) | 2225 / 3946 (4585) |

The setup burst alone, five users: `ls` 715 / 19855 → 596 / 835, `status` 6794 / 10918 → 7019 / 8117, `circle ls` 1237 / 15041 → 1249 / 8075.

Reading it:
- The 10-20 s stalls are gone at five users: `ls` p95 7.7 s → 0.9 s, the worst `status` 14.6 s → 2.8 s outside setup. p50 and the calm p95 outside setup didn't move (they were never the problem).
- What is left is the setup burst: fifteen `status` commands, fifteen watches and the relays starting at the same moment on one machine queue for the same disk. Each command waits its turn for the store locks of its own home (300-1000 ms per acquisition at the peak, with ten processes per home), and the watches apply the fifteen incoming statuses with four fsync'd writes each. No real user produces that burst; spreading the setup's statuses (or measuring on separate machines) would show the latency a user sees.
- At three users nothing was slow to begin with. The two 15 s `status` samples among 197 calm ones (seed 6) started 0.5 s after a device came back from a 40 s pause with its backlog, and ended 15 s later; the harness judges "calm" when a command ends, so they counted. Two reruns of the same seed didn't repeat them.
- Ten users is past what one laptop runs well (20 clients, 30 watches, two relays): `status` is 2-4 s for both, and the setup burst 20 s for both. The worst calm `status` went from 20.3 s to 4.6 s.
- Run-to-run spread is large (one seed's p95 moves by a few hundred ms between runs of the same code); compare several runs before trusting a difference under about 20%. Some of the "after" runs (the second five-user pair and the ten-user one) shared the machine with another soak; they are, if anything, pessimistic.

### Not done (proposals)

- **A fair cross-process lock.** Waiters poll every 50 ms, so under contention a process can lose many rounds in a row (15-20 tries for one acquisition at the burst's peak). A FIFO ticket queue in the store directory would bound the wait at roughly (waiters × hold time). It changes the lock protocol every client version shares, so it wants its own review.
- **Fewer fsyncs per envelope.** Applying one envelope takes four locked, fsync'd writes (claim, peers, events, commit), each with a directory fsync. Batching the peers and events writes into one locked section, or dropping the directory fsync for documents that are rebuilt anyway (events, peers, `fetched`), would roughly halve it. The second trades durability on power loss (not on a crash) for speed, so it is a proposal, not a change here.
- **Lock timeouts as attempts.** A claim counts as an attempt even when it failed only on a lock timeout, so a long lock stall can give up a legitimate envelope after three tries (it happened behind the empty lock). Not counting transient local failures would need a separate bound for poison envelopes that always fail transiently (the soak's ENOSPC poison); that is the review M-A hardening, so it is proposed rather than changed. (An attempt a command abandons because it exits with it still running is no longer counted: see the pre-release review below.)

### Pre-release review: kept envelopes

The first version of this branch made a soak regression (seed 7: a status stuck through the whole heal window, given up unapplied). Two paths combined:
- a watch that answered "keep" because another process held the envelope's claim never saw it again (a relay sends an envelope once per connection, and again only to one that authenticates), and the lock-free claim check made that answer more common;
- with the shorter first drain, short commands more often exited with handlers still running, and each exit counted an attempt against the claim; after three the envelope was given up.

Now a watch handles an envelope it kept again itself (from 2 s, doubling to a minute, 10 times, while its connection lasts; `P2P_KEEP_RETRY_MS` sets the first wait), and a command that gives up on running handlers past its close grace starts no more, gives their claims back without counting an attempt, and lets them apply nothing more.

Repeated quick soaks (three users), one at a time on the same machine, all with this branch's harness at the time (before its last two false-positive fixes), five runs per cell. Counted: runs where a correctness invariant failed (the `latency` invariant failed often in every column on that busy day and isn't counted). "main" is 0894fcf's bundle, "first" the first version of this branch (e0d8088), "fixed" this one.

| seed | main | first | fixed |
|---|---|---|---|
| 7 | 0 / 5 | 2 / 5 (u1 couldn't re-join the circle; a poison message whose pair unfriended in flight, a harness false positive) | 1 / 5 (the same poison false positive) |
| 6 | 0 / 5 | not run | 1 / 5 (a viewer showing a *newer* status whose command had reported failure, a harness false positive) |
| 9 | 2 / 5 (u0 and u1 couldn't re-friend; u1 couldn't re-join the circle) | not run | 0 / 5 |

With both false positives counted as passes: main 2 / 15, fixed 0 / 15, first 1 / 5 on seed 7. The circle re-join failure shows on `main` too (seed 9), so it is not only this branch's; a separate fix is working in that code.
