// Copyright 2026 Ix Infrastructure Inc.
//
// Delivery receipts (§4.3 "Delivery receipts", cap receipts.v1): a live report had a sender's
// sessions say "Delivered" while the recipient never saw the messages (held for approval, or in a
// session nobody watched). The receiving session now says what became of a message, end to end
// encrypted, to the sending session only; with no text, never from a private session, never
// naming the session an ended one's copy went to, rate-limited, and never itself receipted.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { RECEIPT_SID } from "@peer2peer/core/v3";
import { RECEIPT_RATE_ALL, RECEIPT_RATE_HARD, RECEIPT_RATE_PER_USER, receiptRateAllows } from "../receipts.js";
import { sessKey } from "../state.js";
import { flushOutbox } from "../outbox.js";
import { sendMessage } from "../sessions.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-receipts.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
const ids: Record<string, string> = {};

type Ev = { id: string; kind: string; toSession?: string; data: Record<string, unknown> };
const events = async (u: User): Promise<Ev[]> => ((await (await u.app()).state.get("events"))?.items ?? []) as Ev[];
const messageEvent = async (text: string, copy = false) => {
  await ann.ok(["ls"]);
  return (await events(ann)).find((e) => e.kind === "p2p.message" && e.data.text === text && (e.data.unclaimedFor !== undefined) === copy);
};
const receiptsFor = async (id: string) => {
  await ben.ok(["ls"]);
  return (await events(ben)).filter((e) => e.kind === "p2p.receipt" && e.data.receiptId === id);
};
const send = (sid: string, text: string) => ben.ok(["send", "--from-session", "b1", "--to", `${ids.ann}/${sid}`, "--stdin", "--json"], { stdin: text });
const receipt = (event: string, sid: string, outcome: string) => ann.ok(["receipt", event, "--from-session", sid, "--outcome", outcome, "--json"]);

describe("delivery receipts", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    for (const u of [ann, ben]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const code = (await ann.ok(["invite"])).code as string;
    await ben.ok(["join", "--confirmed", code]);
    await ann.ok(["friends"]);
    // a1 and a2 send receipts (their front end says so); a3 is an older client's session.
    for (const sid of ["a1", "a2", "a3"]) {
      await ann.ok(["session", "roster", sid, "--add", ids.ben]);
      await ann.ok(["status", "--session", sid, "--state", "idle", "--label", sid, ...(sid === "a3" ? [] : ["--cap", "receipts.v1"])]);
    }
    await ben.ok(["session", "roster", "b1", "--add", ids.ann]);
    await ben.ok(["ls"]);
  }, 90_000);

  afterAll(async () => {
    await relay?.close();
    ann?.cleanup();
    ben?.cleanup();
  });

  it("held, then shown: each reaches the sending session as a p2p.receipt, with the id and the outcome and no text", async () => {
    const r = await send("a1", "please look");
    expect(r).toMatchObject({ delivered: true, receipts: "requested" });
    const id = r.receiptId as string;
    const ev = await messageEvent("please look");
    expect(ev?.data.receipt).toBe(true);
    // The id never reaches the receiving front end: it reports by event.
    expect(JSON.stringify(ev)).not.toContain(id);
    expect(await receipt(ev!.id, "a1", "held")).toMatchObject({ sent: true, outcome: "held" });
    expect(await receipt(ev!.id, "a1", "held")).toMatchObject({ sent: false, reason: "done" });
    expect(await receipt(ev!.id, "a1", "shown")).toMatchObject({ sent: true, outcome: "shown" });
    // Nothing after a final outcome.
    expect(await receipt(ev!.id, "a1", "declined")).toMatchObject({ sent: false, reason: "done" });
    const got = await receiptsFor(id);
    expect(got.map((e) => e.data.outcome)).toEqual(["held", "shown"]);
    for (const e of got) {
      expect(e.toSession).toBe("b1");
      expect(e.data).toMatchObject({ from: { userId: ids.ann }, own: ids.ann });
      expect(JSON.stringify(e.data)).not.toContain("please look");
    }
  }, 60_000);

  it("only the session the message went to may report it; an unknown event reports nothing", async () => {
    await send("a1", "mine only");
    const ev = await messageEvent("mine only");
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "not-yours" });
    expect(await receipt("p2p.message:nothing-like-this", "a1", "shown")).toMatchObject({ sent: false, reason: "not-asked" });
    const bad = await ann.run(["receipt", ev!.id, "--from-session", "a1", "--outcome", "read", "--json"]);
    expect(bad.json.error).toBe("usage");
  }, 60_000);

  it("an older client's session (no receipts.v1): no rcpt goes out, and the send says receipts are unsupported", async () => {
    const r = await send("a3", "old client");
    expect(r).toMatchObject({ delivered: true, receipts: "unsupported" });
    expect(r.receiptId).toBeUndefined();
    const ev = await messageEvent("old client");
    expect(ev?.data.receipt).toBeUndefined();
    expect(await receipt(ev!.id, "a3", "shown")).toMatchObject({ sent: false, reason: "not-asked" });
  }, 60_000);

  it("a private session sends none", async () => {
    const r = await send("a2", "into a2");
    const ev = await messageEvent("into a2");
    // a2 stops being shared with anyone: private now.
    await ann.ok(["session", "roster", "a2", "--remove", ids.ben]);
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "private" });
    expect(await receiptsFor(r.receiptId as string)).toEqual([]);
    await ann.ok(["session", "roster", "a2", "--add", ids.ben]);
    // The roster that has Ben again rides with a2's next status.
    await ann.ok(["status", "--session", "a2", "--state", "idle", "--label", "a2", "--cap", "receipts.v1"]);
    await ben.ok(["ls"]);
  }, 60_000);

  it("an ended session's copy only ever says `ended`, whatever the session holding it did, and never which session", async () => {
    // a1 ended: its watch's marker names a process that is gone.
    mkdirSync(join(ann.home, "cursors"), { recursive: true });
    writeFileSync(join(ann.home, "cursors", "a1.watch"), JSON.stringify({ pid: 2 ** 22 + 4243, started: 1 }));
    const r = await send("a1", "for the ended one");
    const copy = await messageEvent("for the ended one", true);
    expect(copy?.data).toMatchObject({ unclaimedFor: "a1", receipt: true });
    // Held by another session of Ann's (a2): reported as held, sent as ended.
    expect(await receipt(copy!.id, "a2", "held")).toMatchObject({ sent: true, outcome: "ended" });
    expect(await receipt(copy!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "done" });
    const got = await receiptsFor(r.receiptId as string);
    expect(got.map((e) => e.data.outcome)).toEqual(["ended"]);
    // Exactly the receipt's fields: the sender's own record of where it sent the message (own, ref),
    // never a session of Ann's (no sid, no toSession, nothing about the holder) (pre-release review R1).
    expect(Object.keys(got[0].data).sort()).toEqual(["from", "outcome", "own", "receiptId", "ref"]);
    expect(got[0].data.ref).toBe(r.to.ref);
    writeFileSync(join(ann.home, "cursors", "a1.watch"), JSON.stringify({ pid: process.pid, started: Math.round(Date.now() - process.uptime() * 1000) }));
  }, 60_000);

  it("receipts off: none sent, and statuses stop advertising receipts.v1 (so senders see an older client)", async () => {
    await send("a2", "while off");
    const ev = await messageEvent("while off");
    expect(await ann.ok(["receipts", "off", "--json"])).toMatchObject({ receipts: false });
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "off" });
    await ann.ok(["status", "--session", "a2", "--state", "busy", "--label", "a2", "--cap", "receipts.v1"]);
    await ben.ok(["ls"]);
    const rec = ((await (await ben.app()).state.get("peers")) ?? {})[sessKey(ids.ann, "a2")];
    expect(rec?.status.caps ?? []).not.toContain("receipts.v1");
    expect(await send("a2", "after off")).toMatchObject({ receipts: "unsupported" });
    expect(await ann.ok(["receipts", "on", "--json"])).toMatchObject({ receipts: true });
    await ann.ok(["status", "--session", "a2", "--state", "idle", "--label", "a2", "--cap", "receipts.v1"]);
    await ben.ok(["ls"]);
  }, 60_000);

  it("a receipt for an id this device didn't send that user, or for nothing, is dropped without a trace", async () => {
    const r = await send("a2", "check the sender");
    const app = await ben.app();
    // Ben's record says the message went to someone else: Ann's receipt for it doesn't count.
    await app.state.update("receipts", (cur) => {
      const d = cur!;
      return { next: { ...d, wanted: { ...d.wanted, [r.receiptId]: { ...d.wanted[r.receiptId], to: `p2p:${"z".repeat(52)}` } } }, result: undefined };
    });
    const ev = await messageEvent("check the sender");
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: true });
    // And one for an id nobody sent.
    const a = await ann.app();
    await a.load();
    await a.connectAndDrain();
    await a.deliver(ids.ben, "receipt", { own: ids.ann, sid: RECEIPT_SID }, { receipt: { id: "nobody-sent-this-id", outcome: "shown" } });
    await ben.ok(["ls"]);
    expect((await events(ben)).filter((e) => e.kind === "p2p.receipt" && (e.data.receiptId === r.receiptId || e.data.receiptId === "nobody-sent-this-id"))).toEqual([]);
  }, 60_000);

  it("rate-limited: past RECEIPT_RATE_HARD in a minute, none go out", async () => {
    await send("a2", "one too many");
    const ev = await messageEvent("one too many");
    const a = await ann.app();
    await a.state.update("receipts", (cur) => ({ next: { ...cur!, rate: { by: {}, all: Array.from({ length: RECEIPT_RATE_HARD }, () => Date.now()) } }, result: undefined }));
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "rate-limited" });
  }, 60_000);

  it("R2: a stale status (the session went quiet, or came back on an older client) never decides it: no rcpt, and the message arrives", async () => {
    const app = await ben.app();
    const age = async (sid: string, agoMs: number) =>
      app.state.update("peers", (cur = {}) => {
        const k = sessKey(ids.ann, sid);
        return { next: { ...cur, [k]: { ...cur[k], ts: Date.now() - agoMs } }, result: undefined };
      });
    // Stale: a2's last status (which advertised receipts.v1) is 10 minutes old: the offline path.
    await age("a2", 10 * 60_000);
    const stale = await send("a2", "after a quiet spell");
    expect(stale).toMatchObject({ delivered: true, queued: true, state: "offline", receipts: "unsupported" });
    expect(stale.receiptId).toBeUndefined();
    const ev = await messageEvent("after a quiet spell");
    expect(ev?.data.receipt).toBeUndefined();
    // Downgraded: a2 is back with a client that doesn't advertise receipts.v1 (its newer status).
    await ann.ok(["status", "--session", "a2", "--state", "idle", "--label", "a2"]);
    await ben.ok(["ls"]);
    const down = await send("a2", "to the downgraded one");
    expect(down).toMatchObject({ delivered: true, receipts: "unsupported" });
    expect((await messageEvent("to the downgraded one"))?.data.receipt).toBeUndefined();
    await ann.ok(["status", "--session", "a2", "--state", "idle", "--label", "a2", "--cap", "receipts.v1"]);
    await ben.ok(["ls"]);
  }, 60_000);

  it("issue #3: a copy kept for later (no relay of theirs answered) asks for no receipt when it goes out", async () => {
    await ann.ok(["status", "--session", "a1", "--state", "idle", "--label", "a1", "--cap", "receipts.v1"]);
    await ben.ok(["ls"]);
    const app = await ben.app();
    await app.load();
    await app.connect();
    const pool = app.pool!;
    const real = pool.sendEnvelope.bind(pool);
    // Ann's relays don't answer this once (refused before anything was written): the copy is kept.
    let refused = 0;
    pool.sendEnvelope = async (env, to, tdid, kind, targets) => {
      if (kind === "msg" && to === ids.ann && refused++ === 0) return { sent: [], errors: targets.map((t) => ({ relay: t.relay, code: "unreachable" })) };
      return real(env, to, tdid, kind, targets);
    };
    let r: Awaited<ReturnType<typeof sendMessage>>;
    try {
      r = await sendMessage(app, { fromSession: "b1", to: `${ids.ann}/a1`, text: "kept for later" });
    } finally {
      await app.close();
    }
    expect(refused).toBe(1);
    expect(r).toMatchObject({ delivered: false, queued: true, state: "outbox", receipts: "unsupported" });
    expect(r.receiptId).toBeUndefined();
    // Sent later (as watch does): the copy that arrives doesn't ask, so a client that downgraded meanwhile still takes it.
    const later = await ben.app();
    await later.load();
    await later.connect();
    try {
      expect((await flushOutbox(later, { force: true })).sent).toBe(1);
    } finally {
      await later.close();
    }
    const ev = await messageEvent("kept for later");
    expect(ev).toBeDefined();
    expect(ev?.data.receipt).toBeUndefined();
  }, 60_000);

  it("R3: nothing to change writes nothing", async () => {
    // The rate-limit test above filled the window.
    await (await ann.app()).state.update("receipts", (cur) => ({ next: { ...cur!, rate: { by: {}, all: [] } }, result: undefined }));
    const r = await send("a2", "write once");
    const ev = await messageEvent("write once");
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: true });
    const file = join(ann.home, "cli", "receipts.json");
    const before = statSync(file).mtimeMs;
    await new Promise((res) => setTimeout(res, 20));
    expect(await receipt(ev!.id, "a2", "shown")).toMatchObject({ sent: false, reason: "done" });
    expect(statSync(file).mtimeMs).toBe(before);
    expect(r.receiptId).toBeDefined();
  }, 60_000);

  it("R5: past the global limit each user keeps a fair share; a few busy peers can't use it all", () => {
    const now = Date.now();
    const busy = (n: number) => Array.from({ length: n }, () => now);
    // Four peers at their per-user cap fill RECEIPT_RATE_ALL: a fifth still gets its share.
    const four = { by: Object.fromEntries(["p1", "p2", "p3", "p4"].map((u) => [u, busy(RECEIPT_RATE_PER_USER)])), all: busy(4 * RECEIPT_RATE_PER_USER) };
    expect(four.all.length).toBeGreaterThanOrEqual(RECEIPT_RATE_ALL);
    expect(receiptRateAllows(four, "p5")).toBe(true);
    expect(receiptRateAllows(four, "p1")).toBe(false);
    // The fair share is RECEIPT_RATE_ALL among this minute's users, the new one included.
    const five = { ...four, by: { ...four.by, p5: busy(Math.floor(RECEIPT_RATE_ALL / 5)) }, all: busy(four.all.length + Math.floor(RECEIPT_RATE_ALL / 5)) };
    expect(receiptRateAllows(five, "p5")).toBe(false);
    expect(receiptRateAllows(five, "p6")).toBe(true);
    // The hard ceiling holds for everyone.
    expect(receiptRateAllows({ by: {}, all: busy(RECEIPT_RATE_HARD) }, "p7")).toBe(false);
  });
});
