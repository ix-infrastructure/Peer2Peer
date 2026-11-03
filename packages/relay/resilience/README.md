# Relay resilience and input-validation suite

Each test pushes one relay limit up to and past its configured value, then
checks that the relay keeps every invariant it promises: the process stays up,
memory and disk stay bounded, the event loop stays responsive, and honest
users are unaffected.

```sh
npm run test:resilience   # 30 tests, about 72 s (Mac and Linux/Node 22)
npm run test:fuzz         # 4 tests (fast-check), about 6 s
```

Neither suite runs under `npm test`. Both run in CI only through the
manual-dispatch `relay-resilience` job.

## Scope: a locally started relay only

The suite takes no host, URL or port argument, and nothing in it can be
pointed at another machine. Every test forks its own relay
(`harness/relay-process.ts`, entry `child/relay-child.ts`):

- bound to `127.0.0.1`, with a random port (`PORT=0`) and a fresh temp SQLite file;
- with `DEBUG_STATS=1` on the localhost metrics listener;
- killed at the end of the test, and its temp directory deleted.

The child's URL is built from the port it reports over the IPC channel. The
harness refuses to override `HOST`, `PORT`, `METRICS_HOST`, `DB_PATH` or
`RELAY_URL`, and the child refuses to start if it isn't bound to `127.0.0.1`.
There are no traffic-generating scripts or CLIs. Load comes only from these
vitest files, using the existing fixtures in `src/__tests__/helpers.ts` for
certificates, caps, identity documents and envelopes. Load is small and
capped: what is under test is the relay's limits and invariants, not its peak
throughput.

`global-setup.ts` compiles `src/` (without tests) and the child entry into
`node_modules/.cache/relay-resilience` once per run.

## How a test works

- **Limits** go through the same `LIMIT_*` environment variables operators use, set small so each limit is reached in seconds.
- **Many source addresses from one machine:** the relay runs with `TRUST_PROXY=1`, and each client presents its address in `X-Forwarded-For`. Attackers, the canary and newcomers each use their own address (RFC 5737 / RFC 3849 documentation ranges).
- **Compressed time:** the child's clock is wall time plus an offset. The test advances the offset over IPC (`relay.advance(ms)`), so per-minute and per-hour windows, link TTLs and retention behave as they would in real time without the test waiting for them.
- **Canary:** two honest users, on their own address, exchange a capped message every 100–200 ms for the whole test. Every message is acked as it arrives. The canary reports how many were accepted, delivered and lost, any refusal codes, and delivery latency (send frame written to `env` frame received).
- **Measurements:** `/debug/stats` on the metrics listener. The event-loop delay histogram is reset when the load phase starts and read when it ends. RSS is polled every 200 ms. DB size is the database file plus its WAL and SHM.
- **Reporting:** every test prints one `RESILIENCE {...}` JSON line with what it measured (`grep '^RESILIENCE'`).

## Thresholds (`harness/load.ts` `THRESHOLDS`)

Every test asserts these after its load phase. Some tests add their own
assertions on top.

| Check | Threshold | Why |
|---|---|---|
| Relay process | alive, and `/healthz` returns 200 | The limit is enforced by refusing work, never by dying. |
| Event-loop delay p99 | < 50 ms | Idle baseline is about 15 ms (`monitorEventLoopDelay`, 10 ms resolution). |
| Event-loop delay max during a sweep (#11 only) | < 100 ms in the strict test (11b); 11a keeps the looser p99 < 100 ms and max < 250 ms | A sweep must not freeze every connection. |
| RSS | < 256 MiB absolute, and < 64 MiB growth over the load phase | Load is bounded, so memory must be bounded too. #7 adds a drift bound, below. |
| DB size (db + WAL + SHM) | < the store's hard limit + 16 MiB | For tests that configure a store limit. |
| Canary | 0 lost, 0 refused, latency p99 < 250 ms, max < 1 s | Honest users never pay for an attacker. |

## What each test proves

| # | File | Limits under test | What it proves |
|---|---|---|---|
| 1 | `01-identity` | `identityPublishPerIssPerHour=10`, `…PerIpPerHour=16`, `identityMaxTips=2`, `identityMaxVersions=6` | Publishes past the per-userId and per-IP rates get `rate-limited`, and it is a rate (an hour later X publishes again), not a ban. At most 6 versions are kept. A third concurrent branch tip gets `full`, and a merge brings the tips back to 1. The canary's receiver still publishes its own document meanwhile. |
| 2 | `02-store-quota` | `storeMaxBytes=256 KiB`, `storeHardMaxBytes=384 KiB` | 240 × 4 KB (4× the quota) from one source: every send gets `sent` (eviction, not denial), the store stays ≤ 256 KiB, the attacker's sink keeps only its newest envelopes, in order, and 10 parked canary messages to an offline device all survive and are delivered. |
| 3 | `03-recipient-fairness` | `recipientMaxBytes=64 KiB` | A heavy sender (160 × 2 KB) and an honest sender (6 × 1 KB, interleaved) to one recipient: all 6 honest messages survive, the heavy sender's oldest are evicted, and the recipient holds ≤ 64 KiB. |
| 4 | `04-connections` | `maxUnauthConnections=20`, `maxUnauthPerIp=4`, `maxConnectionsPerIp(v4)=8`, `maxConnectionsPerIss=3`, `connectsPerIpPerMinute=30`, `authsPerIp(v4)PerMinute=12` (the IPv4 knobs are set explicitly, F-5) | A full unauth cap drops its oldest idle socket (4008) instead of refusing anyone, so it stays at 20. Every other cap refuses exactly the excess (429, `full`, `rate-limited`), and authenticating frees a per-IP unauth slot. While any cap is full, a fresh honest device on another address connects and authenticates. |
| 5 | `05-conn-budgets` | `framesPerConnPerMinute=200`, `sendBytesPerConnPerMinute=64 KiB`, `sendBytesPerIpPerMinute=128 KiB` | Frames past the budget get `rate-limited` and the connection stays open. Byte budgets cap per connection and per IP, and another IP is unaffected. Invalid-signature sends get `bad-envelope` until the byte budget is spent and `rate-limited` (no signature work) after it; nothing is stored. A replayed envelope from another sender is refused before any signature work (0.08 ms per reply). Four 40-deep pipelines of valid capped sends keep event-loop delay p99 under 50 ms (was F-2). |
| 6 | `06-links` | `linkOpenPerDevice=2`, `linkOpenPerIp=3`, `linkTotalBytes` = 5 mailboxes, `linkOpsPerIpPerMinute=40` | Opens are refused with `full` per device, per IP and by the global byte reservation, which never exceeds `linkTotalBytes`. Reopening an existing mailbox gets `exists`. A `req` slot holds 4 entries of ≤ 16 KiB (`full`, `too-large`), and `resp` is owner-only (`forbidden`). Unauthenticated lookups are rate-limited per IP. After the TTL, the canary opens a mailbox. |
| 7 | `07-no-ack` | `mailboxEnvelopes=200` | One receiver reads but never acks; another stops reading its socket. 1,200 envelopes of ~60 KB (~70 MB) arrive in six chunks, 3 in 4 for the receiver that isn't reading. RSS is read after every chunk: setting aside the single largest rise (V8's one-off heap reservation step for large strings, 25–40 MB), the remaining rises total < 24 MiB (measured ~4 MiB). A relay that ignored backpressure would add ~9 MB per chunk. Each mailbox holds ≤ 200, the lazy receiver gets exactly 200 again on reconnect, and the stuck one was handed only 231 of the 900 meant for it. |
| 8 | `08-http` | `httpPerIpPerMinute=60`, `chainMaxN=8` | 150 lookups of `/v3/identity/<id>`, `/tips` and `/chain` from one IP: 60 get 200 and 90 get 429, while another IP still reads. Chain walks return ≤ 8 documents. `n=9`, `n=0`, `n=abc`, a bad `to` and bad percent-encoding get 400; an unknown user gets 404; POST gets 405. |
| 9 | `09-ipv6` | `TRUST_PROXY=1`, `maxConnectionsPerIp=4` (/64) and `maxConnectionsPerIpv4=4`, `httpPerIpPerMinute=20` | Rotating addresses within one /64 share one bucket, for sockets and for HTTP. The bucket can't be escaped with a spoofed left-hand XFF entry, `[addr]:port`, upper case or `::` compression. The neighbouring /64 is its own bucket. `::ffff:a.b.c.d` (dotted or hex) shares the IPv4 bucket. |
| 10 | `10-restart` | `storeMaxBytes=128 KiB`, `maxConnectionsPerIp(v4)=6` | SIGKILL mid-flood, then a restart on the same database: `PRAGMA integrity_check` is ok and the `totals` table matches the envelopes. All 12 parked messages and exactly the 5 un-acked live messages are redelivered, and the 5 acked ones are not. After the restart, the per-IP cap and the store quota still hold. Restart takes about 70–90 ms. When the attacker floods again after the restart, all 12 parked canary messages survive (was F-6); when only honest traffic pushes the store over quota after the restart, the attacker's pre-crash data goes first; and a flood spread over 30 addresses, each under the eviction floor, evicts its own groups before a small honest parked group. |
| 11 | `11-sweep` | `SWEEP_INTERVAL_SEC=1`, 120k small envelopes | Sweeps every second while 40k rows expire without a stall: p99 < 100 ms, max < 250 ms, canary healthy; and the strict variant, p99 < 50 ms and max < 100 ms (was F-4). |
| 12 | `12-shared-ipv4` | production defaults | 40, 80 and 300 honest users behind one IPv4 address, each sending one `status` per relay-minute to 10 peers: none refused, every send `sent` (was F-5 past 50 users). |

### Input validation (`fuzz/`, fast-check)

The seed is fixed (20261021) and each property runs 1,000 inputs; override
with `FUZZ_SEED` / `FUZZ_RUNS`. Both are printed at the start of every run.

- **`ws-frames`:** random JSON; structured frames with random field values; valid frames truncated, overwritten, spliced or duplicated; fake JWSs; binary frames; nesting up to 40k deep; frames just under and just over `frameBytes`. Each input goes to an authenticated and to an unauthenticated connection, followed by a probe. After every input:
  - the process is alive;
  - every frame the relay sent is a documented type, and every error carries a documented code;
  - the connection still answers the probe correctly, or closed with a documented close code (1001, 1007, 1009, 4001, 4008, 4029);
  - no `frame handler failed` errors were logged.
- **`http-targets`:** raw TCP requests with arbitrary request targets (percent-encoding fragments, control characters, `//`, absolute-form URLs, 20 KB paths) and methods, as plain requests and as WebSocket upgrades. After every request:
  - the process is alive;
  - the status is one the relay documents;
  - any JSON `error` is a documented one.
  
  The property runs both over every target and over the targets the URL parser accepts. A fixed matrix re-checks the F-1 repros (`//`, `///`, `http://[`, `http://[::1`, `//[::1`) on the public port (plain and upgrade) and on the metrics listener (plain and with Upgrade headers): each must get a clean 400 with the relay up.

## When a test fails

Don't change the relay to make a test pass in this suite's PR. Mark the test
`it.fails` (or `it.skip` with a reason), and record the failure in
[`FINDINGS.md`](./FINDINGS.md): the test, the configured limits, the measured
numbers, and the suspected `file:line`. When a fix lands, the `it.fails` test
starts failing: flip it to `it` and delete the finding.
