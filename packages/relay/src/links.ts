// Copyright 2026 Ix Infrastructure Inc.
//
// Pre-auth link mailboxes (docs/protocol.md §5.7, used by device linking §2.4).
//
// Opened by an authenticated device, keyed by `lid`, alive 10 minutes. One
// `req` slot (up to 4 entries) and one `resp` slot (1 entry). `req` puts and
// all gets are unauthenticated (the relay rate-limits them per IP); a `resp`
// put is accepted only on the connection that opened the mailbox.
//
// Held in memory: a link lives minutes, and a relay restart simply means the
// user starts the link again. Memory is bounded three ways: open mailboxes per
// device and per source IP, a global count, and a global byte budget. The
// budget is RESERVED at open (a mailbox's maximum: every req entry plus the
// resp entry), so a full budget refuses new opens, which are authenticated
// and rate-limited, and never refuses puts into a mailbox already open.

export type LinkSlot = "req" | "resp";

export type LinkResult = "ok" | "not-found" | "full" | "forbidden" | "exists" | "too-large";

interface LinkMailbox {
  ownerConn: number;
  ownerDid: string;
  ownerIp: string;
  expiresAt: number;
  req: string[];
  resp: string[];
}

export interface LinkLimits {
  ttlMs: number;
  reqEntries: number;
  entryBytes: number;
  openPerDevice: number;
  openPerIp: number;
  maxOpen: number;
  totalBytes: number;
}

export const LID_RE = /^[a-z2-7]{26}$/;

export class LinkMailboxes {
  private readonly boxes = new Map<string, LinkMailbox>();
  private reserved = 0;

  /** Bytes reserved per open mailbox. */
  private readonly perBox: number;

  constructor(
    private readonly limits: LinkLimits,
    private readonly now: () => number,
  ) {
    this.perBox = (limits.reqEntries + 1) * limits.entryBytes;
  }

  private live(lid: string): LinkMailbox | undefined {
    const b = this.boxes.get(lid);
    if (b && b.expiresAt <= this.now()) {
      this.boxes.delete(lid);
      this.reserved -= this.perBox;
      return undefined;
    }
    return b;
  }

  open(lid: string, conn: number, did: string, ip: string): LinkResult {
    if (this.live(lid)) return "exists";
    this.sweep();
    let mine = 0;
    let fromIp = 0;
    for (const b of this.boxes.values()) {
      if (b.ownerDid === did) mine++;
      if (b.ownerIp === ip) fromIp++;
    }
    if (
      mine >= this.limits.openPerDevice ||
      fromIp >= this.limits.openPerIp ||
      this.boxes.size >= this.limits.maxOpen ||
      this.reserved + this.perBox > this.limits.totalBytes
    ) {
      return "full";
    }
    this.boxes.set(lid, { ownerConn: conn, ownerDid: did, ownerIp: ip, expiresAt: this.now() + this.limits.ttlMs, req: [], resp: [] });
    this.reserved += this.perBox;
    return "ok";
  }

  put(lid: string, slot: LinkSlot, data: string, conn: number): LinkResult {
    const size = Buffer.byteLength(data, "utf8");
    if (size > this.limits.entryBytes) return "too-large";
    const b = this.live(lid);
    if (!b) return "not-found";
    if (slot === "resp") {
      if (conn !== b.ownerConn) return "forbidden";
      if (b.resp.length >= 1) return "full";
    } else if (b.req.length >= this.limits.reqEntries) {
      return "full";
    }
    // Fits: the open reserved room for every entry this mailbox can hold.
    b[slot].push(data);
    return "ok";
  }

  get(lid: string, slot: LinkSlot): string[] | undefined {
    const b = this.live(lid);
    return b ? [...b[slot]] : undefined;
  }

  sweep(): number {
    let n = 0;
    for (const lid of [...this.boxes.keys()]) if (!this.live(lid)) n++;
    return n;
  }

  get size(): number {
    return this.boxes.size;
  }

  /** Bytes reserved across every open link mailbox. */
  get reservedBytes(): number {
    return this.reserved;
  }
}
