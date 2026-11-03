// Copyright 2026 Ix Infrastructure Inc.
//
// Restricted connections (§2.7 restore) and no-return, from the pre-release review:
//  H1  a revoked device can't lock its owner out: restricted connections have
//      their own cap, a deadline and their own identity limiter, charged only
//      for a parsable document; a retired did gets no connection at all;
//  H2  a restricted publisher can only extend the top of the history, never fork;
//  M1  the relay enforces no-return, and `by` must be a key holder.

import { afterEach, describe, expect, it } from "vitest";
import { authed, makeDevice, makeDoc, makeIdentity, startRelay, TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay;
afterEach(async () => {
  await r?.close();
});

async function publish(c: TestClient, jws: unknown) {
  return c.request({ t: "identity", doc: jws });
}

async function restrictedClient(device: Parameters<TestClient["auth"]>[0]): Promise<TestClient> {
  const c = await TestClient.connect(r.url);
  expect(await c.auth(device)).toEqual({ t: "ok", restricted: true });
  return c;
}

/** An identity whose v1 lists `keeper` (a listed device), with an unlisted, never-revoked spare cert. */
async function setup() {
  const id = makeIdentity();
  const keeper = makeDevice(id, r.nowSec());
  const kc = await authed(r, keeper);
  const v1 = makeDoc(id, r.nowSec(), { devices: [keeper.did] });
  expect(await publish(kc, v1.jws)).toMatchObject({ t: "ok" });
  return { id, keeper, kc, v1 };
}

describe("H1: restricted connections can't lock the owner out", () => {
  it("have their own per-userId cap, apart from maxConnectionsPerIss", async () => {
    r = await startRelay({ limits: { maxConnectionsPerIss: 2, restrictedPerIss: 2 } });
    const { id, keeper, kc } = await setup();
    const spares = [0, 1, 2].map(() => makeDevice(id, r.nowSec()));
    const a = await restrictedClient(spares[0]);
    const b = await restrictedClient(spares[1]);
    const c = await TestClient.connect(r.url);
    expect(await c.auth(spares[2])).toEqual({ t: "error", code: "full" });
    // A listed device still gets in: restricted connections don't count against maxConnectionsPerIss.
    const k2 = await authed(r, keeper);
    for (const x of [a, b, k2, kc]) await x.close();
  });

  it("are closed if not upgraded in time", async () => {
    r = await startRelay({ limits: { restrictedTimeoutSec: 1 } });
    const { id } = await setup();
    const c = await restrictedClient(makeDevice(id, r.nowSec()));
    expect(await c.closed).toBe(4001);
  });

  it("are closed when their certificate expires", async () => {
    r = await startRelay({ limits: { restrictedTimeoutSec: 60 } });
    const { id } = await setup();
    const short = makeDevice(id, r.nowSec(), { iat: r.nowSec() - 10, exp: r.nowSec() + 1 });
    const c = await restrictedClient(short);
    const t0 = Date.now();
    expect(await c.closed).toBe(4001);
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it("charge their own identity limiter, and only for a parsable document", async () => {
    r = await startRelay({ limits: { identityPublishPerIssPerHour: 3, restrictedIdentityPerIssPerHour: 1 } });
    const { id, keeper, kc, v1 } = await setup();
    const c = await restrictedClient(makeDevice(id, r.nowSec()));
    // Junk is refused without charging anything.
    for (let i = 0; i < 10; i++) expect(await publish(c, 1)).toMatchObject({ code: "bad-identity" });
    for (let i = 0; i < 5; i++) expect(await publish(c, "not.a.jws")).toMatchObject({ code: "bad-identity" });
    // The owner's own budget is untouched: two more listed publishes fit (one was used by setup).
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did] });
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    // A parsable document charges the restricted limiter once per connection (N-L1: a restore that
    // back-fills sends several in a row); the next connection's attempt is over the 1/h budget.
    const fork = (n: number) => makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [], name: `f${n}` });
    for (let n = 1; n <= 4; n++) expect((await publish(c, fork(n).jws)).code).not.toBe("rate-limited");
    await c.close();
    const c2 = await restrictedClient(makeDevice(id, r.nowSec()));
    expect(await publish(c2, fork(9).jws)).toMatchObject({ code: "rate-limited" });
    await c2.close();
  });

  it("are refused for a did a held version dropped (retired), even with a valid certificate", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const lost = makeDevice(id, r.nowSec());
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did, lost.did] });
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did] });
    expect(await publish(kc, v3.jws)).toMatchObject({ t: "ok" });
    const c = await TestClient.connect(r.url);
    expect(await c.auth(lost)).toEqual({ t: "error", code: "auth-failed" });
  });

  it("of a did that becomes retired are closed", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const spare = makeDevice(id, r.nowSec());
    const c = await restrictedClient(spare);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did, spare.did] });
    // Listing it upgrades nothing here (it's another connection's publish), but dropping it retires it.
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did] });
    expect(await publish(kc, v3.jws)).toMatchObject({ t: "ok" });
    expect(await c.closed).toBe(4001);
  });
});

describe("H2: a restricted publisher can't fork", () => {
  it("only a version extending every tip is accepted; a sibling of the head is forbidden", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did] });
    expect(await publish(kc, v2.jws)).toMatchObject({ t: "ok" });
    const restored = makeDevice(id, r.nowSec());
    const c = await restrictedClient(restored);
    // A fork off v1 (a non-tip ancestor) would split the allowlist: refused.
    const fork = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [restored.did], name: "fork" });
    expect(await publish(c, fork.jws)).toMatchObject({ code: "forbidden" });
    // A new root is refused too.
    const root = makeDoc(id, r.nowSec(), { ver: 9, devices: [restored.did], prev: null });
    expect((await publish(c, root.jws)).t).toBe("error");
    // On top of the head: accepted, and the connection becomes a full one.
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [restored.did] });
    expect(await publish(c, v3.jws)).toMatchObject({ t: "ok" });
    expect(await c.request({ t: "revoke", capid: "AAAAAAAAAAAAAAAAAAAAAA" })).toMatchObject({ t: "ok" });
    expect((await fetch(`${r.http}/v3/identity/${id.userId}/tips`).then((x) => x.json())).tips).toEqual([v3.jws]);
    await c.close();
  });
});

describe("R3: state-based acceptance at the relay; no-return is the clients'", () => {
  it("re-listing a revoked did is accepted (clients reject it), but the did gets no connection while its versions are held", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const lost = makeDevice(id, r.nowSec());
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did, lost.did] });
    await publish(kc, v2.jws);
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did] });
    await publish(kc, v3.jws);
    expect(await (await TestClient.connect(r.url)).auth(lost)).toEqual({ t: "error", code: "auth-failed" });
    const back = makeDoc(id, r.nowSec(), { ver: 4, prev: v3.hash, devices: [keeper.did, lost.did] });
    expect(await publish(kc, back.jws)).toMatchObject({ t: "ok" });
  });

  it("a merge's devices must lie within both parents'", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const k2 = makeDevice(id, r.nowSec());
    const one = makeDevice(id, r.nowSec());
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did, k2.did] });
    await publish(kc, v2.jws);
    const a = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did, k2.did, one.did], name: "a" });
    const b = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [keeper.did, k2.did], name: "b" });
    await publish(kc, a.jws);
    await publish(kc, b.jws);
    const [hi, lo] = a.hash > b.hash ? [a, b] : [b, a];
    const adds = makeDoc(id, r.nowSec(), { ver: 4, prev: hi.hash, merge: lo.hash, devices: [keeper.did, one.did] });
    expect(await publish(kc, adds.jws)).toMatchObject({ code: "bad-identity" });
    const merge = makeDoc(id, r.nowSec(), { ver: 4, prev: hi.hash, merge: lo.hash, devices: [keeper.did, k2.did] });
    expect(await publish(kc, merge.jws)).toMatchObject({ t: "ok" });
  });

  it("refuses a version whose `by` isn't a key holder", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const other = makeDevice(id, r.nowSec());
    const bad = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did, other.did], keyholders: [other.did] });
    expect(await publish(kc, bad.jws)).toMatchObject({ code: "bad-identity" });
  });
});

describe("re-review: ancestry-scoped no-return, restricted merges, promotion, health checks", () => {
  it("a restricted publisher merges three tips pairwise, then extends", async () => {
    r = await startRelay();
    const { id, keeper, kc, v1 } = await setup();
    const tips = ["a", "b", "c"].map((n) => makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [keeper.did], name: n }));
    for (const t of tips) expect(await publish(kc, t.jws)).toMatchObject({ t: "ok" });
    const restored = makeDevice(id, r.nowSec());
    const c = await restrictedClient(restored);
    const sorted = [...tips].sort((x, y) => (x.hash > y.hash ? -1 : 1));
    const m1 = makeDoc(id, r.nowSec(), { ver: 3, prev: sorted[0].hash, merge: sorted[1].hash, devices: [keeper.did] });
    expect(await publish(c, m1.jws)).toMatchObject({ t: "ok" });
    const m2 = makeDoc(id, r.nowSec(), { ver: 4, prev: m1.hash, merge: sorted[2].hash, devices: [keeper.did] });
    expect(await publish(c, m2.jws)).toMatchObject({ t: "ok" });
    const ext = makeDoc(id, r.nowSec(), { ver: 5, prev: m2.hash, devices: [keeper.did, restored.did] });
    expect(await publish(c, ext.jws)).toMatchObject({ t: "ok" });
    expect(await c.request({ t: "revoke", capid: "AAAAAAAAAAAAAAAAAAAAAA" })).toMatchObject({ t: "ok" });
    await c.close();
  });

  it("every restricted connection of the newly listed device is promoted, not only the publishing one", async () => {
    r = await startRelay();
    const { id, v1 } = await setup();
    const restored = makeDevice(id, r.nowSec());
    const pub = await restrictedClient(restored);
    const other = await restrictedClient(restored);
    const v2 = makeDoc(id, r.nowSec(), { ver: 2, prev: v1.hash, devices: [restored.did] });
    expect(await publish(pub, v2.jws)).toMatchObject({ t: "ok" });
    expect(await other.request({ t: "revoke", capid: "AAAAAAAAAAAAAAAAAAAAAA" })).toMatchObject({ t: "ok" });
    await pub.close();
    await other.close();
  });

  it("a loopback health check without X-Forwarded-For doesn't warn about TRUST_PROXY", async () => {
    r = await startRelay({ config: { trustProxy: 1 } });
    for (let i = 0; i < 3; i++) expect((await fetch(`${r.http}/healthz`)).status).toBe(200);
    expect(r.logs.some((l) => l.includes("fewer hops"))).toBe(false);
    await fetch(`${r.http}/.well-known/p2p-relay.json`);
    expect(r.logs.some((l) => l.includes("fewer hops"))).toBe(true);
  });
});
