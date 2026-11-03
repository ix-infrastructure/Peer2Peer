// Copyright 2026 Ix Infrastructure Inc.
// §5.6 identity documents on the relay, with the §2.5 chain, fork and merge rules.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { jwsHash } from "../crypto.js";
import { authed, DAY, makeDevice, makeDoc, makeIdentity, startRelay, type Device, type Identity, type TestClient, type TestRelay } from "./helpers.js";

let r: TestRelay;
let id: Identity;
let k1: Device;
let k2: Device;
let d3: Device;
let c: TestClient;

beforeEach(async () => {
  r = await startRelay();
  id = makeIdentity();
  k1 = makeDevice(id, r.nowSec());
  k2 = makeDevice(id, r.nowSec());
  d3 = makeDevice(id, r.nowSec());
  c = await authed(r, k1);
});
afterEach(async () => {
  await r.close();
});

const publish = (doc: string, client = c) => client.request({ t: "identity", doc });

async function get(path: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${r.http}${path}`);
  return { status: res.status, body: res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text() };
}

/** v1 → v2 → v3, linear. */
async function linear(n = 3, devices?: string[]) {
  const docs: { jws: string; hash: string }[] = [];
  let prev: string | null = null;
  for (let ver = 1; ver <= n; ver++) {
    const d = makeDoc(id, r.nowSec(), { ver, prev, devices: devices ?? [k1.did, k2.did, d3.did] });
    expect(await publish(d.jws)).toMatchObject({ t: "ok" });
    docs.push(d);
    prev = d.hash;
  }
  return docs;
}

describe("publish and fetch", () => {
  it("accepts a chain and serves the head, tips and the chain walk", async () => {
    const docs = await linear(3);
    expect(await get(`/v3/identity/${id.userId}`)).toEqual({ status: 200, body: { doc: docs[2].jws } });
    expect(await get(`/v3/identity/${id.userId}/tips`)).toEqual({ status: 200, body: { tips: [docs[2].jws] } });
    const chain = await get(`/v3/identity/${id.userId}/chain?to=${docs[2].hash}&n=64`);
    expect(chain.body.docs).toEqual([docs[2].jws, docs[1].jws, docs[0].jws]);
    const short = await get(`/v3/identity/${id.userId}/chain?to=${docs[2].hash}&n=2`);
    expect(short.body.docs).toEqual([docs[2].jws, docs[1].jws]);
    const mid = await get(`/v3/identity/${id.userId}/chain?to=${docs[1].hash}`);
    expect(mid.body.docs).toEqual([docs[1].jws, docs[0].jws]);
  });

  it("is idempotent", async () => {
    const [d1] = await linear(1);
    expect(await publish(d1.jws)).toMatchObject({ t: "ok" });
    expect(r.store.counts().identityDocs).toBe(1);
  });

  it("accepts any first version when it holds none (a relay added later)", async () => {
    const d5 = makeDoc(id, r.nowSec(), { ver: 5, prev: jwsHash("something"), devices: [k1.did] });
    expect(await publish(d5.jws)).toMatchObject({ t: "ok" });
    expect((await get(`/v3/identity/${id.userId}`)).body.doc).toBe(d5.jws);
  });

  it("rejects a gap: prev not held", async () => {
    const docs = await linear(2);
    const v4 = makeDoc(id, r.nowSec(), { ver: 4, prev: jwsHash("v3 the relay never saw"), devices: [k1.did] });
    expect(await publish(v4.jws)).toMatchObject({ t: "error", code: "identity-gap" });
    // A second ver 1 is a gap too: the relay already holds a chain.
    const other1 = makeDoc(id, r.nowSec(), { ver: 1, devices: [k1.did], name: "fresh-start" });
    expect(await publish(other1.jws)).toMatchObject({ t: "error", code: "identity-gap" });
    // Back-filling the missing version makes it acceptable.
    const v3 = makeDoc(id, r.nowSec(), { ver: 3, prev: docs[1].hash, devices: [k1.did, k2.did, d3.did] });
    expect(await publish(v3.jws)).toMatchObject({ t: "ok" });
    const v4b = makeDoc(id, r.nowSec(), { ver: 4, prev: v3.hash, devices: [k1.did] });
    expect(await publish(v4b.jws)).toMatchObject({ t: "ok" });
  });

  it("rejects a version that doesn't extend prev by one", async () => {
    const docs = await linear(2);
    const skip = makeDoc(id, r.nowSec(), { ver: 4, prev: docs[1].hash, devices: [k1.did] });
    expect(await publish(skip.jws)).toMatchObject({ code: "bad-identity" });
  });

  it("only an authenticated device of doc.iss may publish", async () => {
    const other = makeIdentity();
    const doc = makeDoc(other, r.nowSec(), { devices: [] });
    expect(await publish(doc.jws)).toMatchObject({ code: "forbidden" });
  });

  it("rejects documents that don't verify", async () => {
    const forger = makeIdentity();
    const real = makeDoc(id, r.nowSec(), { devices: [k1.did] });
    const [h, , s] = real.jws.split(".");
    const forgedPayload = makeDoc(forger, r.nowSec(), { devices: [k1.did] }).jws.split(".")[1];
    expect(await publish(`${h}.${forgedPayload}.${s}`)).toMatchObject({ code: "bad-identity" });
    expect(await publish("nope")).toMatchObject({ code: "bad-identity" });
    const tooManyRelays = makeDoc(id, r.nowSec(), { relays: [1, 2, 3, 4, 5, 6].map((i) => `wss://r${i}.test/v3`) });
    expect(await publish(tooManyRelays.jws)).toMatchObject({ code: "bad-identity" });
    const nonCanonical = makeDoc(id, r.nowSec(), { relays: ["wss://Relay.Test/v3/"] });
    expect(await publish(nonCanonical.jws)).toMatchObject({ code: "bad-identity" });
  });

  it("keeps serving and accepting expired documents (expiry is receiver-side)", async () => {
    const d1 = makeDoc(id, r.nowSec(), { iat: r.nowSec() - 40 * DAY, devices: [k1.did] });
    expect(await publish(d1.jws)).toMatchObject({ t: "ok" });
    expect((await get(`/v3/identity/${id.userId}`)).status).toBe(200);
  });

  it("returns 404 for unknown users and bad paths, 400 for bad chain queries", async () => {
    const docs = await linear(1);
    expect((await get(`/v3/identity/${makeIdentity().userId}`)).status).toBe(404);
    expect((await get(`/v3/identity/not-a-user`)).status).toBe(404);
    expect((await get(`/v3/identity/${id.userId}/nope`)).status).toBe(404);
    expect((await get(`/v3/identity/${id.userId}/chain?to=${docs[0].hash}&n=65`)).status).toBe(400);
    expect((await get(`/v3/identity/${id.userId}/chain?to=${docs[0].hash}&n=0`)).status).toBe(400);
    expect((await get(`/v3/identity/${id.userId}/chain`)).status).toBe(400);
    expect((await get(`/v3/identity/${id.userId}/chain?to=${jwsHash("x")}`)).status).toBe(404);
  });
});

describe("forks and merges", () => {
  async function fork() {
    const [v1, v2] = await linear(2);
    // Two key holders publish v3 at once: one drops d3, the other drops k2.
    const a = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [k1.did, k2.did], name: "a" });
    const b = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [k1.did, d3.did], name: "b" });
    expect(await publish(a.jws)).toMatchObject({ t: "ok" });
    const kc2 = await authed(r, k2);
    expect(await publish(b.jws, kc2)).toMatchObject({ t: "ok" });
    const [hi, lo] = a.hash > b.hash ? [a, b] : [b, a];
    return { v1, v2, a, b, hi, lo };
  }

  it("keeps both branches; head is the highest ver (tie: higher jwsHash); tips lists both", async () => {
    const { hi, lo } = await fork();
    expect((await get(`/v3/identity/${id.userId}`)).body.doc).toBe(hi.jws);
    expect((await get(`/v3/identity/${id.userId}/tips`)).body.tips).toEqual([hi.jws, lo.jws]);
  });

  it("applies the intersection of the tips' device lists to auth (rule 6)", async () => {
    await fork();
    // k2 is only in branch a, d3 only in branch b. Each was dropped by the other
    // branch (a revocation, §2.5), so neither may authenticate at all, not even restricted.
    for (const dev of [k2, d3]) {
      const { TestClient } = await import("./helpers.js");
      const x = await TestClient.connect(r.url);
      expect(await x.auth(dev)).toEqual({ t: "error", code: "auth-failed" });
    }
    const x = await authed(r, k1);
    await x.close();
  });

  it("accepts a merge whose devices are in both tips, and walks both parents", async () => {
    const { v1, v2, hi, lo } = await fork();
    const merge = makeDoc(id, r.nowSec(), { ver: 4, prev: hi.hash, merge: lo.hash, devices: [k1.did] });
    expect(await publish(merge.jws)).toMatchObject({ t: "ok" });
    expect((await get(`/v3/identity/${id.userId}`)).body.doc).toBe(merge.jws);
    expect((await get(`/v3/identity/${id.userId}/tips`)).body.tips).toEqual([merge.jws]);
    const chain = (await get(`/v3/identity/${id.userId}/chain?to=${merge.hash}`)).body.docs as string[];
    expect(chain[0]).toBe(merge.jws);
    expect(new Set(chain.slice(1, 3))).toEqual(new Set([hi.jws, lo.jws]));
    expect(chain.slice(3)).toEqual([v2.jws, v1.jws]);
  });

  it("rejects a merge that adds a device", async () => {
    const { hi, lo } = await fork();
    const merge = makeDoc(id, r.nowSec(), { ver: 4, prev: hi.hash, merge: lo.hash, devices: [k1.did, k2.did] });
    expect(await publish(merge.jws)).toMatchObject({ code: "bad-identity" });
  });

  it("rejects a merge with the parents swapped or the wrong ver", async () => {
    const { hi, lo } = await fork();
    const swapped = makeDoc(id, r.nowSec(), { ver: 4, prev: lo.hash, merge: hi.hash, devices: [k1.did] });
    expect(await publish(swapped.jws)).toMatchObject({ code: "bad-identity" });
    const wrongVer = makeDoc(id, r.nowSec(), { ver: 5, prev: hi.hash, merge: lo.hash, devices: [k1.did] });
    expect(await publish(wrongVer.jws)).toMatchObject({ code: "bad-identity" });
  });

  it("rejects a merge whose merge parent isn't held", async () => {
    const { hi } = await fork();
    const merge = makeDoc(id, r.nowSec(), { ver: 4, prev: hi.hash, merge: jwsHash("unknown"), devices: [k1.did] });
    expect(await publish(merge.jws)).toMatchObject({ code: "identity-gap" });
  });

  it("a merge across tips of different vers uses ver = max + 1", async () => {
    const { a, b } = await fork();
    const a4 = makeDoc(id, r.nowSec(), { ver: 4, prev: a.hash, devices: [k1.did, k2.did] });
    expect(await publish(a4.jws)).toMatchObject({ t: "ok" });
    const merge = makeDoc(id, r.nowSec(), { ver: 5, prev: a4.hash, merge: b.hash, devices: [k1.did] });
    expect(await publish(merge.jws)).toMatchObject({ t: "ok" });
  });
});

describe("scope and retention", () => {
  it("serves only documents that list this relay; stops serving when the head drops it", async () => {
    const d1 = makeDoc(id, r.nowSec(), { devices: [k1.did] });
    await publish(d1.jws);
    const d2 = makeDoc(id, r.nowSec(), { ver: 2, prev: d1.hash, devices: [k1.did], relays: ["wss://elsewhere.test/v3"] });
    expect(await publish(d2.jws)).toMatchObject({ t: "ok" });
    expect((await get(`/v3/identity/${id.userId}`)).status).toBe(404);
    expect((await get(`/v3/identity/${id.userId}/tips`)).status).toBe(404);
    expect((await get(`/v3/identity/${id.userId}/chain?to=${d1.hash}`)).status).toBe(404);
  });

  it("keeps versions 90 days, and the head until it has been expired 90 days", async () => {
    const docs = await linear(3); // exp = iat + 29 days
    r.clock.advance(91 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.counts().identityDocs).toBe(1);
    expect((await get(`/v3/identity/${id.userId}`)).body.doc).toBe(docs[2].jws);
    // Head expired at day 29; at day 118 it has been expired 89 days: still kept.
    r.clock.advance(27 * DAY * 1000);
    await r.relay.sweep();
    expect((await get(`/v3/identity/${id.userId}`)).status).toBe(200);
    // At day 120 it has been expired 91 days: the documents are gone (H1), but
    // a tombstone keeps the last allowlist (N4).
    r.clock.advance(2 * DAY * 1000);
    await r.relay.sweep();
    expect((await get(`/v3/identity/${id.userId}`)).status).toBe(404);
    expect(r.store.counts().identityDocs).toBe(0);
    const tomb = r.store.identityIndex(id.userId)!;
    expect(tomb.leftAt).not.toBeNull();
    expect(new Set(tomb.allowed)).toEqual(new Set([k1.did, k2.did, d3.did]));
    // The tombstone itself goes after 91 more days.
    r.clock.advance(92 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.identityIndex(id.userId)).toBeUndefined();
  });

  it("keeps every fork tip past 90 days", async () => {
    const [, v2] = await linear(2);
    const a = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [k1.did], name: "a" });
    const b = makeDoc(id, r.nowSec(), { ver: 3, prev: v2.hash, devices: [k1.did], name: "b" });
    await publish(a.jws);
    await publish(b.jws);
    r.clock.advance(91 * DAY * 1000);
    await r.relay.sweep();
    expect(r.store.counts().identityDocs).toBe(2);
  });
});
