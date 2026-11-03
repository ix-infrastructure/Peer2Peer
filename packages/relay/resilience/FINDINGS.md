# Resilience findings

What the resilience and input-validation suites find against `main`. The suite
never changes relay source.

- **A still-failing test** is marked `it.fails`, so the suite stays green until a fix lands. When the fix lands, that test starts failing (an `it.fails` that passes is reported as an error): flip it to `it` and move its entry to "Fixed".
- **A result too close to the line** to be either stable `it` or stable `it.fails` is `it.skip` with the reason, and is listed here as open.

Re-checked against `main` at 62e800d, which includes the pre-release relay hardening fixes. The open findings were then fixed in `fix/relay-hardening-5` (see "Fixed"). Numbers are from both runs:

- **Mac:** Apple silicon, Node 26.5.
- **Linux:** `node:22.23.2-bookworm`, the CI image.

Line numbers are against 62e800d.

---

## Open

None. F-2, F-4, F-5 and F-6 were fixed in `fix/relay-hardening-5` (below).

---

## Accepted

### L-2 (pre-release re-review): many sources under the floor

*Accepted: inherent to largest-first fairness.*

An attacker who controls about 17 or more sources, each kept just under the eviction floor, makes any honest group *above* the floor the next eviction victim. The floor is 1/16 of the quota: 256 MiB for the store, 16 MiB per recipient.

- **Exposed:**
  - a shared NAT holding more than 256 MiB in the store;
  - an honest sender holding more than 16 MiB for one recipient. This case also needs the attacker to hold a cap for that recipient.
- **Why it's accepted:**
  - It is much narrower than before, since only groups above the floor are exposed.
  - Removing it entirely would need per-identity accounting instead of per-source accounting, and an attacker with free identities defeats that anyway.

---

## Fixed

Numbers after the fix are from 5 consecutive full runs of `npm run test:resilience`:
- **Mac:** Apple silicon, Node 26.5.
- **Linux:** `node:22.23.2-bookworm`, the CI image (Docker on the same Mac).

Every run passed 29/29.

### F-2: one connection's pipelined sends stalled the event loop for about 2 ms per send

*Fixed in `fix/relay-hardening-5`.*

- **Test (now normal `it`):** `05-conn-budgets` › "a pipelined burst of 40 valid capped sends …"
- **What changed:**
  - **Native Ed25519.** Signatures are verified with `node:crypto` (OpenSSL) for messages up to 16 KiB.
    - The strict rules are kept explicitly: keys pass core's `assertStrongEd25519PublicKey` (canonical, not small order, torsion-free) before any signature under them, and `S < L` is checked.
    - A differential test (`src/__tests__/native-ed25519.test.ts`) covers core's v2 and v3 vectors, random signatures, and over 1,000 malformed signatures, keys and messages. Native rejects exactly what core's noble-strict verifier rejects.
    - Larger messages use core's strict verifier. Node copies the whole input on every native one-shot verify, and with ~60 KB envelopes that churn added 20–40 MB of RSS in #7.
  - **Cached caps.** Verified caps are cached by JWS hash, with the stateless result only. Expiry, the per-send context, revocation, `uses` and the allowlist still run on every send.
  - **Frames yield.** `ws` runs with `allowSynchronousEvents: false`, so each socket's frames are processed one per macrotask. The receiver stops reading the socket meanwhile (TCP backpressure), so nothing queues in relay memory.
- **Before / after** (160 sends, 4 × 40 pipelined):

  | | Before (Mac / Linux) | After, 5 runs (Mac / Linux) |
  |---|---|---|
  | Relay time per send | 1.95–2.03 / 2.06 ms | 0.34–0.45 / 0.27–0.31 ms |
  | Event-loop delay p99 / max | 77.9–83 / 78.7–83 ms; Linux 82.7 / 82.7 | Mac 11.1–11.9 / 11.6–13.4 ms; Linux 13.5–15.0 / 13.7–17.2 ms |

### F-4 (residual): sweeps blocked for 40–125 ms at a time on 120k small envelopes

*Fixed in `fix/relay-hardening-5`.*

- **Tests:**
  - `11-sweep` › strict 11b (p99 < 50 ms, max < 100 ms), un-skipped and now a normal `it`.
  - 11a (p99 < 100 ms, max < 250 ms) still runs.
- **What changed:**
  - **Expiry batches** aim at about 10 ms each: the row count adapts between 20 and 2,000.
  - **The sweep prelude** (cap state, identity versions, device rows, identity tombstones) deletes at most 200 rows per table per step and yields between steps. The full `counts()` scan is gone from the sweep; it uses a counter read.
  - **P4 invites** follow the same rules:
    - The sweep deletes expired invites in adaptive batches (about 10 ms each), yielding between them. It updates `invite_iss` row by row, and expired `evicted` tombstones go in batches through a new `expires_at` index.
    - `inviteBytes()` is now a counter, not a `sum()` over every blob, and `init()` rebuilds the per-userId totals in chunks instead of one aggregate in the constructor.
    - An invite put on a full store runs one bounded sweep step, and eviction takes already-expired invites before any live one.
    - Measured on a Mac with 20,000 expired 2 KiB invites: the single-statement sweep held the event loop 270–283 ms; the new sweep stays under the test's 75 ms bound.
  - **WAL checkpoints run on a worker thread.** SQLite's automatic checkpoint ran inside whichever commit crossed the threshold, on the main thread, copying WAL pages and syncing the file. That was a 20–30 ms stall every few hundred deletes on the Linux CI disk.
    - Now `wal_autocheckpoint = 0`, and a worker with its own connection runs `PRAGMA wal_checkpoint(PASSIVE)` every 100 ms. PASSIVE never blocks writers.
    - While a pass leaves frames uncopied, the worker runs it again at once (up to 32 times). Under steady writes a single PASSIVE pass rarely finishes, and SQLite only rewinds the WAL when a pass has, so before this the WAL grew for as long as writes continued (12c reached 190 MB in one run, with a 1.2 s stall). With the repeat, 12c ends at about 8 MB.
    - If the worker dies, autocheckpoint is turned back on.
    - **Watchdog (pre-release review):** the worker reports every checkpoint. A pass counts as progress if it copied every frame, copied more than the pass before, or the WAL rewound. Under sustained writes passes rarely end fully caught up but keep advancing; a reader pinning an old snapshot (L-3) stops them at the same frame. If no pass makes progress within 30 s, the main thread re-enables autocheckpoint, warns, and restarts the worker. If the WAL passes 256 MiB, it re-enables autocheckpoint and warns.
    - `journal_size_limit` is 64 MiB.
- **Before / after:**

  | | Before | After, 5 runs (Mac / Linux) |
  |---|---|---|
  | 11b p99 / max | 41–60 / 78–126 ms (Mac); Linux 43–68 / 48–162 ms with only batching | Mac 16.4–22.3 / 19.0–64.0 ms; Linux 16.5–17.0 / 17.5–25.4 ms |

### F-5: more than 50 honest users behind one IPv4 address were turned away

*Fixed in `fix/relay-hardening-5`.*

- **Tests:**
  - `12-shared-ipv4` › 80 users (now normal `it`).
  - New: 300 users.
- **What changed:** three per-address limits have separate IPv4 defaults; an IPv6 /64 keeps the old values.

  | | IPv4 | IPv6 /64 |
  |---|---|---|
  | Connections | `maxConnectionsPerIpv4` 512 | 64 |
  | New devices per day | `newDevicesPerIpv4PerDay` 1,000 | 50 |
  | Auths per minute | `authsPerIpv4PerMinute` 600 | 60 |

  - All of these stay bounded by the global caps and the per-userId limits.
  - **Pool protection (pre-release review):**
    - past 80% of `maxConnections`, every address gets the strict per-IP cap;
    - when the pool is full, room comes only from a bucket holding more than the strict per-IP cap (the biggest one). In that bucket the userId with the most connections loses its least recently active one, a newcomer address may cause at most 10 evictions a minute, and with no bucket over the cap the newcomer is refused. The eviction runs only after the newcomer's upgrade succeeds (pre-release re-review M-1, L-4);
    - past 80% of `maxDevices`, IPv4 gets the strict new-device allowance.
  - Tests 4b, 4e and 9 set the IPv4 knobs explicitly, so they still prove the limits.
  - The trade-off is documented in `docs/run-a-relay.md`.
- **Before / after** (identical on Mac and Linux):
  - **80 users, before:** 50 joined and 30 were rate-limited; 445 sent and 55 undeliverable.
  - **After:** 80 users: 80 joined, 800/800 sent. 300 users: 300 joined, 3,000/3,000 sent.
  - The canary was healthy in every run.

### F-6: after a restart, a flooder's mail was split across two source groups, and the honest sender was evicted first

*Fixed in `fix/relay-hardening-5`.*

- **Tests:**
  - `10-restart` › "after a restart, the parked canary mail survives … a renewed flood" (now normal `it`).
  - New: "… when only honest traffic pushes the store over quota, the attacker's old data goes before the parked canary mail".
  - New (pre-release review): "… a flood spread across many sources (each under the eviction floor) evicts its own groups, not small honest parked mail".
- **What changed (as revised after the pre-release review):**
  - **The sender pays first, above its fair share.** When the group of the envelope being stored holds more than its fair share (the quota divided by the number of groups, and at least a floor of 1/16 of the quota), its own oldest envelopes go.
    - Below that share, an honest sender writing to a full mailbox never evicts its own older mail.
    - Resilience #3 caught this: a version with "above the floor" alone did evict it.
  - **Otherwise, the largest group goes**, whatever process tagged it. Strictly, that's the largest among the groups above the floor, and, when none is above it, the largest overall.
  - **No generation is preferred.** The first version of this fix preferred current-process groups, which made small honest pre-restart groups the victims of a flood spread under the floor. The generation prefix is gone.
  - Old groups stay separate anonymous groups, so the R-M1 property holds.
  - It applies to both the store quota and the per-recipient quota.
- **Before / after** (identical on Mac and Linux):
  - **Before:** 11 of 12 parked canary messages survived the renewed flood.
  - **After:** 12 of 12 in every run, and 12 of 12 in the honest-traffic variant.

### F-1: a request target the URL parser rejects crashed the relay

*Fixed before launch: every request-target parse goes through `parseTarget` (`src/server.ts:49`).*

- **Tests (now normal `it`):** `fuzz/http-targets.fuzz.test.ts`
  - "no request target crashes the relay or yields an undocumented status or error": 1,000 inputs, every target.
  - "the F-1 repros … get a clean 400 on every listener".
- **Retested:** `//`, `///`, `http://[`, `http://[::1` and `//[::1`, each four ways:
  - the public port as a plain request;
  - the public port with Upgrade headers;
  - the metrics listener as a plain request;
  - the metrics listener with Upgrade headers.

  All 20 get `400` and the relay stays up, on Mac and Linux, with no error logs.
- **Was:** `GET //` + Upgrade killed the process with an uncaught `ERR_INVALID_URL` (old `server.ts:651`); the metrics listener died the same way (`:528`); plain requests got `500 internal` (`:569`).

### F-3: while the unauthenticated-socket cap was full, nobody could log in

*Fixed before launch.*

- **What changed:**
  - When the cap is full, the oldest unauthenticated socket is dropped with 4008 instead of refusing the newcomer (`src/server.ts:722`).
  - New `maxUnauthPerIp` (default 8, `src/server.ts:719`).
  - `unauthTimeoutSec` is down to 15 s.
- **Tests:**
  - `04-connections` › "an honest newcomer can still connect while the unauth cap is full" (now normal `it`): newcomer `ok`.
  - "holds unauthenticated sockets at maxUnauthConnections by dropping the oldest": 30 sockets from 15 addresses, all opened, the 10 oldest closed with 4008, 20 left unauthenticated.
  - New: "caps unauthenticated sockets per IP at maxUnauthPerIp": 4 open, 3 refused 429; authenticating frees a slot.

---

## Observations (no failing test)

- **405 is not rate-limited.** Non-GET/HEAD methods are answered before the HTTP rate limiter runs. Each answer is cheap, but it is unmetered.
- **Delivery past the mailbox cap.** A receiver that stops reading its socket got 231–264 envelopes once it resumed, more than `mailboxEnvelopes=200`. The extra ones were already in socket buffers when the cap evicted the stored copies. The rest were never sent (backpressure). Expected.
- **One-off heap step under large envelopes.** RSS rises 0–40 MB once, as V8 grows its heap for 60 KB strings, then plateaus. #7 sets that step aside when it judges flatness; the remaining drift is 3.6–9.2 MiB.
