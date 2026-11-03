// Copyright 2026 Ix Infrastructure Inc.

// When this session's Ix footprint (ext-ix's x:ix.footprint state, SPEC §8)
// is recomputed and published: 10 s after the last edit (trailing), at most
// once every 30 s, one at a time, and again every 5 min while it stays
// published (so peers keep it live). `p2p ix footprint --publish` does the
// work (it also spaces computations and skips an unchanged footprint); what it
// prints is never read beyond its outcome, so a footprint never reaches the
// model. A run without the extension, without Ix, or outside a repo with a
// remote stops asking after the first answer, silently.

export const FOOTPRINT_DEBOUNCE_MS = 10_000
export const FOOTPRINT_MIN_GAP_MS = 30_000
export const FOOTPRINT_KEEPALIVE_MS = 5 * 60_000 + 5_000

/** Answers that mean "not here, not this run": no more asking, and nothing said. */
export const FOOTPRINT_OFF = new Set(['extension_missing', 'ix_missing', 'not_a_repo', 'no_remote', 'usage', 'cli_missing'])
// `no_hmac_key` (a git that didn't answer in time, a shallow clone) is retried, backing off.
export const FOOTPRINT_RETRY_MS = 60_000
export const FOOTPRINT_RETRY_MAX_MS = 60 * 60_000

export type FootprintOutcome = { ok: true } | { ok: false; error: string }

export type FootprintDeps = {
  now: () => Promise<number>
  after: (ms: number, fn: () => void) => { cancel(): void }
  /** The run is live, the extension loaded and status sharing on. */
  isActive: () => boolean
  /** Runs `p2p ix footprint --session <sid> --publish`. */
  publish: () => Promise<FootprintOutcome>
}

export class FootprintTrigger {
  private timer: { cancel(): void } | null = null
  private isRunning = false
  private isAgain = false
  private lastAt = -Infinity
  /** After `no_hmac_key`: no run before this, doubling each time (reset by a run that succeeds). */
  private holdUntil = -Infinity
  private retries = 0
  /** No extension, no Ix, no repo: off for the rest of the run. */
  isOff = false
  runs = 0

  constructor(private readonly deps: FootprintDeps) {}

  /** An edit: (re)starts the 10 s debounce. */
  edited(): void {
    if (this.isOff) return
    this.arm(FOOTPRINT_DEBOUNCE_MS)
  }

  stop(): void {
    this.isOff = true
    this.timer?.cancel()
    this.timer = null
  }

  private arm(ms: number): void {
    this.timer?.cancel()
    this.timer = this.deps.after(ms, () => {
      this.timer = null
      void this.fire().catch(() => undefined)
    })
  }

  private async fire(): Promise<void> {
    if (this.isOff || !this.deps.isActive()) return
    if (this.isRunning) {
      this.isAgain = true

      return
    }
    const now = await this.deps.now()
    const wait = Math.max(this.lastAt + FOOTPRINT_MIN_GAP_MS, this.holdUntil) - now
    if (wait > 0) {
      this.arm(wait)

      return
    }
    this.isRunning = true
    this.lastAt = now
    this.runs++
    let r: FootprintOutcome
    try {
      r = await this.deps.publish()
    } catch {
      r = { ok: false, error: 'failed' }
    } finally {
      this.isRunning = false
    }
    if (!r.ok && FOOTPRINT_OFF.has(r.error)) {
      this.stop()

      return
    }
    if (!r.ok && r.error === 'no_hmac_key') {
      this.holdUntil = now + Math.min(FOOTPRINT_RETRY_MAX_MS, FOOTPRINT_RETRY_MS * 2 ** this.retries)
      this.retries++
      this.arm(this.holdUntil - now)

      return
    }
    if (r.ok) this.retries = 0
    if (this.isAgain) {
      this.isAgain = false
      this.arm(FOOTPRINT_DEBOUNCE_MS)
    } else if (!this.timer) this.arm(FOOTPRINT_KEEPALIVE_MS)
  }
}
