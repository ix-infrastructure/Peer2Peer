// Copyright 2026 Ix Infrastructure Inc.
//
// §4.3 "Extension state kinds" (cap xstate.v1, footprint P2): a state kind
// goes to the session's status audience, only to recipients whose live
// sessions advertise xstate.v1; it is stored latest-wins with a ttl, never
// logged as an event (so `watch`, and the mod behind it, never see one); it is
// size-capped and rate-limited on both sides.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EXT_STATE_MAX_BYTES, parsePlaintextV3, STATUS_CAP_XSTATE, type AcceptedMessageV3 } from "@peer2peer/core/v3";
import { App } from "../app.js";
import { main } from "../cli.js";
import { extContext } from "../ext-host.js";
import { checkExtension, ExtensionRegistry, type P2PExtension } from "../extensions.js";
import { receiving } from "../inbound.js";
import { getSession } from "../sessions.js";
import { CliState, sessKey } from "../state.js";
import { OverlayDocBackend } from "../readonly.js";
import {
  liveStates,
  onStateEnvelope,
  stateDevices,
  xstateCost,
  XSTATE_BYTES_PER_USER,
  XSTATE_KINDS_PER_SESSION,
  XSTATE_MAX_RECORDS,
  XSTATE_RATE_WINDOWS_MAX,
  XSTATE_SENDER_UPDATES_PER_MIN,
  XSTATE_UPDATES_PER_MIN,
  XSTATE_VALUES_PER_USER,
  asIndex,
  senderDoc,
} from "../xstate.js";
import { CliError } from "../errors.js";
import { sleep, startRelay, User, type TestRelay } from "./harness.js";

const KIND = "x:ix.footprint";
/** A stand-in for ext-ix: one state kind, whose body must be {n}. */
const testExt: P2PExtension = {
  api: 1,
  graphTargets: 1,
  ns: "ix",
  name: "@peer2peer/ext-ix",
  version: "0.0.0-test",
  state: { [KIND]: { ttl: 60 } },
  receive: (i) => {
    const b = i.body as { n?: unknown } | null;
    if (!b || typeof b.n !== "number") return { ok: false, reason: "not a footprint" };
    return { ok: true, rendered: { digest: `n=${b.n}` }, keep: { n: b.n } };
  },
};
const reg = new ExtensionRegistry([{ ext: testExt, from: "test" }]);

/** `p2p <args> --json` with the test extension loaded. */
async function runX(u: User, args: string[]): Promise<any> {
  const lines = { out: [] as string[], err: [] as string[] };
  const code = await main([...args, "--json"], { env: u.env, io: u.io(lines), extensions: reg });
  process.exitCode = 0;
  if (code !== 0) throw new Error(`${u.name}: p2p ${args.join(" ")} failed (${code}): ${lines.out.join("\n")}\n${lines.err.join("\n")}`);
  return JSON.parse(lines.out.at(-1) ?? "null");
}

/** An App of `u` with the test extension, receiving. */
async function appX(u: User): Promise<App> {
  const app = await u.app();
  app.extensions = reg;
  await app.load();
  receiving(app);
  return app;
}

const ctxOf = (app: App) => extContext(app, testExt, { out: () => undefined, err: () => undefined }, true, async () => false);

describe("checkExtension: state declarations", () => {
  it("only kinds of its own namespace, with a valid cap and ttl", () => {
    expect(checkExtension({ extension: testExt }, "ix").ext).toBe(testExt);
    const bad = (state: unknown) => checkExtension({ extension: { ...testExt, state } }, "ix").why;
    expect(bad({ "x:acme.badge": {} })).toMatch(/not an x:ix/);
    expect(bad({ "x:ix.footprint": { ttl: 5 } })).toMatch(/ttl/);
    expect(bad({ "x:ix.footprint": { ttl: 99999 } })).toMatch(/ttl/);
    // x:acme.<32 characters> is a valid kind, but `<kind>.v1` would be over 40 characters.
    const long = `x:acme.${"a".repeat(32)}`;
    expect(checkExtension({ extension: { ...testExt, ns: "acme", state: { [long]: {} } } }, "acme").why).toMatch(/too long for its cap/);
    expect(bad([])).toMatch(/malformed/);
  });
});

describe("the state marker in core", () => {
  const pt = (o: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify({ ext: { v: 1, body: {} }, fallback: "f", ...o }));
  it("parses state:{ttl}, strictly", () => {
    expect(parsePlaintextV3(KIND, pt({ state: { ttl: 600 } }))).toMatchObject({ state: { ttl: 600 } });
    expect(parsePlaintextV3(KIND, pt({}))).not.toHaveProperty("state");
    for (const bad of [{ ttl: 1 }, { ttl: 3601 }, { ttl: 60.5 }, { ttl: 60, x: 1, crit: ["x"] }, [], "60"]) expect(() => parsePlaintextV3(KIND, pt({ state: bad }))).toThrow(/state/);
  });
});

let relay: TestRelay;
let alice: User;
let bob: User;
let carol: User;
const ids: Record<string, string> = {};
const R = "wss://relay-xstate.test/v3";

describe("state kinds over a relay", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    alice = new User("alice", t);
    bob = new User("bob", t);
    // carol stands for an older client: her statuses carry no caps, so she never advertises xstate.v1.
    carol = new User("carol", t, { P2P_STATUS_CAPS: "0" });
    for (const u of [alice, bob, carol]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    for (const u of [alice, carol]) {
      const inv = await bob.ok(["invite", "--link"]);
      await u.ok(["accept", inv.link]);
      await bob.ok(["friends"]);
    }
    await bob.ok(["session", "roster", "bs1", "--add", ids.alice, "--add", ids.carol]);
    await alice.ok(["session", "roster", "as1", "--add", ids.bob]);
    await carol.ok(["session", "roster", "cs1", "--add", ids.bob]);
    // Their statuses tell bob what each understands; bob's makes his session live for them.
    const a = await runX(alice, ["status", "--session", "as1", "--state", "busy", "--label", "web"]);
    expect(a.status.caps).toEqual(expect.arrayContaining([STATUS_CAP_XSTATE, "x:ix.footprint.v1"]));
    await carol.ok(["status", "--session", "cs1", "--state", "busy", "--label", "web"]);
    await runX(bob, ["status", "--session", "bs1", "--state", "busy", "--label", "api"]);
  }, 60_000);

  afterAll(async () => {
    await relay?.close().catch(() => {});
    for (const u of [alice, bob, carol]) u?.cleanup();
  });

  it("round trip: to the state-aware peer only, stored with its kept body, never an event", async () => {
    const app = await appX(bob);
    let r;
    try {
      r = await ctxOf(app).publish({ fromSession: "bs1", kind: KIND, v: 1, body: { n: 1 }, fallback: "Ix footprint: 1 symbol" });
    } finally {
      await app.close();
    }
    expect(r.ttl).toBe(60);
    expect(r.delivered.map((d) => d.userId)).toEqual([ids.alice]);
    expect(r.skipped).toEqual([{ userId: ids.carol, address: expect.any(String), reason: expect.stringContaining(STATUS_CAP_XSTATE) }]);

    // alice's ls: a bounded summary, no body.
    const row = (await runX(alice, ["ls"])).peers.find((p: any) => p.own === ids.bob && p.sid === "bs1");
    expect(row.xstate).toEqual([{ kind: KIND, at: expect.any(Number), expiresAt: expect.any(Number), fallback: "Ix footprint: 1 symbol", bytes: expect.any(Number) }]);
    expect(JSON.stringify(row)).not.toContain('"n":1');
    // The extension reads the kept body.
    const ax = await appX(alice);
    try {
      const st = await ctxOf(ax).peerState(KIND);
      expect(st).toEqual([expect.objectContaining({ own: ids.bob, sid: "bs1", kind: KIND, v: 1, body: { n: 1 }, fallback: "Ix footprint: 1 symbol", self: false })]);
      const peer = (await ctxOf(ax).peers()).find((p) => p.own === ids.bob && p.sid === "bs1");
      expect(peer?.xstate?.[KIND]?.body).toEqual({ n: 1 });
      // Never an event: nothing in the log that watch prints from.
      const log = (await ax.state.get("events"))?.items ?? [];
      expect(log.filter((e) => e.kind === "p2p.ext")).toEqual([]);
    } finally {
      await ax.close();
    }
    const watched = await alice.watch("as1", 1200);
    expect(watched.filter((e) => e.kind === "p2p.ext")).toEqual([]);
    // Without the extension a state-aware client keeps the fallback only (the body is never interpreted).
    const plain = (await alice.ok(["ls"])).peers.find((p: any) => p.own === ids.bob && p.sid === "bs1");
    expect(plain.xstate[0].fallback).toBe("Ix footprint: 1 symbol");
    // bob's own ls shows his own value too.
    const mine = (await runX(bob, ["ls"])).peers.find((p: any) => p.own === ids.bob && p.sid === "bs1");
    expect(mine.xstate.map((x: any) => x.kind)).toEqual([KIND]);
  });

  it("the old-client recipient never receives one: not stored, not logged", async () => {
    const app = await carol.app();
    await app.load();
    receiving(app);
    try {
      await app.connectAndDrain();
      expect(await liveStates(app)).toEqual([]);
      expect(((await app.state.get("events"))?.items ?? []).filter((e) => e.kind === "p2p.ext")).toEqual([]);
    } finally {
      await app.close();
    }
    const row = (await carol.ok(["ls"])).peers.find((p: any) => p.own === ids.bob);
    expect(row).not.toHaveProperty("xstate");
  });

  it("the sender's rate limit: one update per kind and session every 5 s", async () => {
    const app = await appX(bob);
    try {
      const err = await ctxOf(app)
        .publish({ fromSession: "bs1", kind: KIND, v: 1, body: { n: 9 }, fallback: "too soon" })
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(CliError);
      expect((err as CliError).code).toBe("rate_limited");
    } finally {
      await app.close();
    }
  });

  it("replace: a later value wins; ttl: it lapses", async () => {
    await sleep(5_100);
    const app = await appX(bob);
    try {
      await ctxOf(app).publish({ fromSession: "bs1", kind: KIND, v: 1, body: { n: 2 }, fallback: "Ix footprint: 2 symbols", ttl: 30 });
    } finally {
      await app.close();
    }
    const ax = await appX(alice);
    try {
      const st = await ctxOf(ax).peerState(KIND);
      expect(st).toHaveLength(1);
      expect(st[0]).toMatchObject({ body: { n: 2 }, fallback: "Ix footprint: 2 symbols" });
      expect(st[0].expiresAt - Date.now()).toBeLessThanOrEqual(30_000);
      // Past its ttl it is gone (the session is still live then).
      expect(await liveStates(ax, { kind: KIND }, Date.now() + 31_000)).toEqual([]);
      expect(await liveStates(ax, { kind: KIND }, Date.now() + 1_000)).toHaveLength(1);
    } finally {
      await ax.close();
    }
  });

  it("size caps: a body over 16 KiB is refused before anything is sent; state kinds can't be sent as events", async () => {
    const app = await appX(bob);
    try {
      const big = { n: 1, pad: "x".repeat(EXT_STATE_MAX_BYTES) };
      const err = await ctxOf(app)
        .publish({ fromSession: "bs2", kind: KIND, v: 1, body: big, fallback: "big" })
        .catch((e: unknown) => e);
      expect((err as CliError).code).toBe("too_large");
      const sent = await ctxOf(app)
        .send({ fromSession: "bs1", to: ids.alice, kind: KIND, v: 1, body: { n: 1 }, fallback: "f" })
        .catch((e: unknown) => e);
      expect((sent as CliError).message).toMatch(/state kind: publish it/);
      const other = await ctxOf(app)
        .publish({ fromSession: "bs1", kind: "x:ix.note", v: 1, body: {}, fallback: "f" })
        .catch((e: unknown) => e);
      expect((other as CliError).message).toMatch(/isn't one of/);
    } finally {
      await app.close();
    }
  });

  it("pre-release review M2: a participant can't overwrite the owner's status (nor send idle or roster for it)", async () => {
    // alice's session as1 lets bob in; bob holds its roster from her statuses.
    const app = await bob.app();
    await app.load();
    receiving(app);
    try {
      await app.connectAndDrain();
      const ro = await app.store.getRoster(ids.alice, "as1");
      expect(ro).toBeDefined();
      const target = { own: ids.alice, sid: "as1" };
      for (const [kind, pt] of [
        ["status", { status: { state: "idle", label: "spoofed", summary: "owned by bob" }, roster: ro!.jws }],
        ["idle", { reason: "exited", roster: ro!.jws }],
      ] as const) {
        // To alice: hers is the record of the session it would overwrite.
        const d = await app.deliver(ids.alice, kind, target, pt);
        expect(d.relays.length).toBeGreaterThan(0);
      }
    } finally {
      await app.close();
    }
    const lines = { out: [] as string[], err: [] as string[] };
    await main(["ls", "--json"], { env: alice.env, io: alice.io(lines), extensions: reg });
    process.exitCode = 0;
    const own = JSON.parse(lines.out.at(-1) ?? "null").peers.find((p: any) => p.own === ids.alice && p.sid === "as1");
    expect(own).toMatchObject({ label: "web", state: "busy" });
    expect(JSON.stringify(own)).not.toContain("spoofed");
    expect(lines.err.join("\n")).toMatch(/not-session-owner/);
  });

  it("a recipient with a second live session from an older client is skipped (and that device never gets one)", async () => {
    // alice's second session runs an older client: its status carries no caps.
    const aa = await alice.app();
    await aa.load();
    receiving(aa);
    try {
      const sess = await getSession(aa, "as2");
      await aa.connectAndDrain();
      if (!sess.parts.includes(ids.bob)) {
        await alice.ok(["session", "roster", "as2", "--add", ids.bob]);
      }
      const s2 = await getSession(aa, "as2");
      await aa.deliver(ids.bob, "status", { own: aa.userId, sid: "as2" }, { status: { state: "busy", label: "old" }, roster: s2.jws });
    } finally {
      await aa.close();
    }
    await runX(bob, ["ls"]);
    const app = await appX(bob);
    try {
      const peers = (await app.state.get("peers")) ?? {};
      expect(stateDevices(peers, ids.alice, { userId: app.userId, did: app.did })).toEqual([]);
      await sleep(5_100);
      const r = await ctxOf(app).publish({ fromSession: "bs1", kind: KIND, v: 1, body: { n: 3 }, fallback: "f" });
      expect(r.delivered).toEqual([]);
      expect(r.skipped.map((s) => s.userId).sort()).toEqual([ids.alice, ids.carol].sort());
    } finally {
      await app.close();
    }
  });
});

describe("receiving: flood, spacing and bounds (onStateEnvelope)", () => {
  let home: string;
  let app: App;
  const ME = "p2p:me";
  const PEER = "p2p:peer";
  let ts = Date.now() - 120_000;
  /** A fabricated accepted envelope: the receive chain already verified it. */
  const env = (o: { from?: string; own?: string; sid?: string; ts?: number }) =>
    ({ envelope: { from: o.from ?? o.own ?? PEER, own: o.own ?? PEER, sid: o.sid ?? "s1", fdid: "d_peer", ts: o.ts ?? (ts += 6_000) } }) as unknown as AcceptedMessageV3;
  const pt = (kind = KIND, body: unknown = { n: 1 }, ttl = 600) => ({ kind: kind as `x:${string}.${string}`, ext: { v: 1, body }, fallback: "f", state: { ttl } });
  const fromOf = (userId: string) => ({ userId, address: `${userId}@x`, self: false });
  const from = fromOf(PEER);
  const held = async (own?: string) => (await liveStates(app)).filter((r) => own === undefined || r.own === own);
  /** Live statuses for every session the values below belong to. */
  const live = async (owners: string[], sids: number) => {
    const now = Date.now();
    const peers: Record<string, unknown> = {};
    for (const own of owners) for (let i = 0; i < sids; i++) peers[sessKey(own, `s${i}`)] = { own, sid: `s${i}`, did: "d_peer", ts: now, status: { state: "busy", label: "x" } };
    await app.state.put("peers", peers as never);
  };

  beforeAll(async () => {
    home = mkdtempSync(join(tmpdir(), "p2p-xstate-"));
    app = new App({ env: { P2P_HOME: home }, io: { out: () => undefined, err: () => undefined } });
    Object.defineProperty(app, "userId", { value: ME });
    Object.defineProperty(app, "did", { value: "d_me" });
    await live([PEER], 200);
  });

  afterAll(async () => {
    await app.close().catch(() => {});
    rmSync(home, { recursive: true, force: true });
  });

  it("only the session's owner; never over 16 KiB; older values lose; faster than 5 s apart is dropped", async () => {
    expect(await onStateEnvelope(app, env({ from: "p2p:other" }), pt(), from)).toBe("not-owner");
    expect(await onStateEnvelope(app, env({}), pt(KIND, { pad: "x".repeat(EXT_STATE_MAX_BYTES) }), from)).toBe("too-large");
    const t0 = (ts += 6_000);
    expect(await onStateEnvelope(app, env({ ts: t0 }), pt(KIND, { n: 1 }), from)).toBe("stored");
    expect(await onStateEnvelope(app, env({ ts: t0 - 1 }), pt(KIND, { n: 0 }), from)).toBe("older");
    expect(await onStateEnvelope(app, env({ ts: t0 + 1_000 }), pt(KIND, { n: 2 }), from)).toBe("rate-limited");
    expect(await onStateEnvelope(app, env({ ts: t0 + 5_000 }), pt(KIND, { n: 3 }), from)).toBe("stored");
    expect((await held()).map((r) => `${r.own}|${r.sid}|${r.kind}`)).toEqual([`${PEER}|s1|${KIND}`]);
    expect(((await app.state.get("events"))?.items ?? []).length).toBe(0);
  });

  it("L1: a kind the loaded extension that owns the namespace doesn't declare as state keeps only the fallback", async () => {
    app.extensions = reg;
    try {
      expect(await onStateEnvelope(app, env({ sid: "s3" }), pt("x:ix.note", { secret: "body" }), from)).toBe("stored");
      const r = (await held()).find((x) => x.kind === "x:ix.note");
      expect(r?.body).toBeUndefined();
      expect(r?.fallback).toBe("f");
      expect(r?.extError).toMatch(/isn't a state kind of @peer2peer\/ext-ix/);
    } finally {
      app.extensions = undefined;
    }
  });

  it("at most 8 kinds per session", async () => {
    for (let i = 0; i < XSTATE_KINDS_PER_SESSION; i++) expect(await onStateEnvelope(app, env({ sid: "s2" }), pt(`x:ix.k${i}`), from)).toBe("stored");
    expect(await onStateEnvelope(app, env({ sid: "s2" }), pt("x:ix.k99"), from)).toBe("too-many-kinds");
  });

  it("per sender: at most 64 values and 64 KiB charged (a tiny value costs at least 1 KiB), their oldest first", async () => {
    const body = { pad: "y".repeat(15_000) };
    for (let i = 10; i < 16; i++) expect(await onStateEnvelope(app, env({ sid: `s${i}` }), pt(KIND, body), from)).toBe("stored");
    let recs = await held(PEER);
    expect(recs.reduce((n, r) => n + xstateCost(r), 0)).toBeLessThanOrEqual(XSTATE_BYTES_PER_USER);
    expect(recs.some((r) => r.sid === "s15")).toBe(true);
    expect(recs.some((r) => r.sid === "s10")).toBe(false);
    // 120 tiny values across 120 sessions: charged at least 1 KiB each, so far fewer than 120 stay.
    for (let i = 40; i < 160; i++) await onStateEnvelope(app, env({ sid: `s${i}` }), pt(KIND, {}), from);
    recs = await held(PEER);
    expect(recs.length).toBeLessThanOrEqual(XSTATE_VALUES_PER_USER);
    expect(recs.reduce((n, r) => n + xstateCost(r), 0)).toBeLessThanOrEqual(XSTATE_BYTES_PER_USER);
    expect(recs.some((r) => r.sid === "s159")).toBe(true);
    expect(xstateCost({ bytes: 10, fallback: "f", kind: KIND, sid: "s1" })).toBeGreaterThanOrEqual(1024);
  }, 60_000);

  it("M1: senders filling the global cap never evict another sender's value; the biggest holder gives up theirs first", async () => {
    const BOB = "p2p:bob";
    const many = Array.from({ length: 12 }, (_, i) => `p2p:flood${i}`);
    await live([PEER, BOB, ...many], 70);
    // bob's single value is the oldest of all.
    expect(await onStateEnvelope(app, env({ own: BOB, sid: "s0" }), pt(KIND, { n: 1 }), fromOf(BOB))).toBe("stored");
    for (const own of many) for (let i = 0; i < 70; i++) await onStateEnvelope(app, env({ own, sid: `s${i}` }), pt(KIND, {}), fromOf(own));
    const all = await held();
    expect(all.length).toBeLessThanOrEqual(XSTATE_MAX_RECORDS);
    expect(all.some((r) => r.own === BOB && r.sid === "s0")).toBe(true);
    const counts = many.map((own) => all.filter((r) => r.own === own).length);
    expect(Math.max(...counts)).toBeLessThanOrEqual(XSTATE_VALUES_PER_USER);
    // Evicted from whoever held the most: the floods end up within one value of each other.
    expect(Math.max(...counts) - Math.min(...counts)).toBeLessThanOrEqual(1);
  }, 120_000);

  it(`a flooding (sender, session): at most ${XSTATE_UPDATES_PER_MIN} updates a minute, other sessions unaffected`, async () => {
    const FL = "p2p:flooder";
    await live([FL, "p2p:busy"], 20);
    const verdicts: string[] = [];
    for (let i = 0; i < XSTATE_UPDATES_PER_MIN + 10; i++) verdicts.push(await onStateEnvelope(app, env({ own: FL, sid: "s1" }), pt(`x:ix.f${i % 8}`), fromOf(FL)));
    expect(verdicts.filter((v) => v === "flood")).toHaveLength(10);
    expect(verdicts.slice(-5)).toEqual(Array(5).fill("flood"));
    // L3: the same sender's other session still gets through.
    expect(await onStateEnvelope(app, env({ own: FL, sid: "s2" }), pt(KIND), fromOf(FL))).toBe("stored");
  }, 60_000);

  it(`N1: a sender making up session ids is capped at ${XSTATE_SENDER_UPDATES_PER_MIN} a minute, and their document stays bounded`, async () => {
    const WIDE = "p2p:wide";
    await live([], 0);
    const verdicts: Record<string, number> = {};
    // Fast and machine-independent: the receiver's clock is fixed (one minute window for all of them),
    // and its state is an in-memory overlay on this app's (reads fall through, writes stay in memory).
    const fast = Object.create(app) as App;
    Object.defineProperty(fast, "state", { value: new CliState(home, undefined, new OverlayDocBackend(app.state.backend)) });
    const now = Date.now();
    const N = 400; // > the 240 cap, and > XSTATE_RATE_WINDOWS_MAX session windows
    for (let i = 0; i < N; i++) {
      const v = await onStateEnvelope(fast, env({ own: WIDE, sid: `w${i}` }), pt(KIND, {}), fromOf(WIDE), now);
      verdicts[v] = (verdicts[v] ?? 0) + 1;
    }
    expect(verdicts).toEqual({ stored: XSTATE_SENDER_UPDATES_PER_MIN, flood: N - XSTATE_SENDER_UPDATES_PER_MIN });
    const doc = (await fast.state.backend.read(senderDoc(WIDE))) as { recs: object; rate: object };
    expect(Object.keys(doc.rate).length).toBeLessThanOrEqual(XSTATE_RATE_WINDOWS_MAX);
    expect(Object.keys(doc.recs).length).toBeLessThanOrEqual(XSTATE_VALUES_PER_USER);
    expect(JSON.stringify(doc).length).toBeLessThan(XSTATE_BYTES_PER_USER + XSTATE_RATE_WINDOWS_MAX * 64);
  }, 30_000);

  it("N2 + N3: on first use the index is recomputed from the documents; an empty document is deleted", async () => {
    const fresh = new App({ env: { P2P_HOME: home }, io: { out: () => undefined, err: () => undefined } });
    Object.defineProperty(fresh, "userId", { value: ME });
    Object.defineProperty(fresh, "did", { value: "d_me" });
    try {
      const b = fresh.state.backend;
      const now = Date.now();
      const val = (own: string, sid: string) => ({ own, sid, did: "d", kind: KIND, ts: now, at: now, ttl: 600, v: 1, fallback: "f", bytes: 10 });
      const [A, B, C, D] = ["p2p:ra", "p2p:rb", "p2p:rc", "p2p:rd"];
      await b.write(senderDoc(A), { own: A, recs: { [`s1|${KIND}`]: val(A, "s1"), [`s2|${KIND}`]: val(A, "s2") }, rate: {} });
      await b.write(senderDoc(B), { own: B, recs: {}, rate: {} });
      const index = asIndex(await b.read("xstate"));
      await b.write("xstate", { v: 2, users: { ...index.users, [A]: { doc: senderDoc(A), n: 99, cost: 1 }, [B]: { doc: senderDoc(B), n: 5, cost: 1 }, [C]: { doc: senderDoc(C), n: 3, cost: 1 } } });
      expect(await onStateEnvelope(fresh, env({ own: D, sid: "s1" }), pt(), fromOf(D))).toBe("stored");
      const after = asIndex(await b.read("xstate")).users;
      expect(after[A]).toMatchObject({ n: 2 });
      expect(after[B]).toBeUndefined();
      expect(after[C]).toBeUndefined();
      expect(after[D]).toMatchObject({ n: 1 });
      expect(await b.read(senderDoc(B))).toBeUndefined();
    } finally {
      await fresh.close();
    }
  });
});
