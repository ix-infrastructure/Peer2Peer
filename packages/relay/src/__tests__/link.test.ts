// Copyright 2026 Ix Infrastructure Inc.
// §5.7 pre-auth link mailboxes, as used by §2.4 device linking.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "@peer2peer/core";
import { b32Encode } from "../crypto.js";
import { authed, makeDevice, makeIdentity, startRelay, TestClient, type Device, type TestRelay } from "./helpers.js";

let r: TestRelay;
let linker: Device;
let lc: TestClient;

const newLid = () => b32Encode(randomBytes(20)).slice(0, 26);

beforeEach(async () => {
  r = await startRelay({ limits: { linkOpsPerIpPerMinute: 1000 } });
  linker = makeDevice(makeIdentity(), r.nowSec());
  lc = await authed(r, linker);
});
afterEach(async () => {
  await r.close();
});

describe("link mailboxes", () => {
  it("runs the §2.4 flow: open, unauthenticated req put, opener reads, opener answers, new device reads", async () => {
    const lid = newLid();
    expect(await lc.request({ t: "link-open", lid })).toMatchObject({ t: "ok" });

    const newDevice = await TestClient.connect(r.url); // never authenticates
    expect(await newDevice.request({ t: "link-put", lid, slot: "req", data: "sealed-request" })).toMatchObject({ t: "ok" });

    expect(await lc.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ t: "link", lid, slot: "req", entries: ["sealed-request"] });
    expect(await newDevice.request({ t: "link-get", lid, slot: "resp" })).toMatchObject({ entries: [] });

    expect(await lc.request({ t: "link-put", lid, slot: "resp", data: "sealed-bundle" })).toMatchObject({ t: "ok" });
    expect(await newDevice.request({ t: "link-get", lid, slot: "resp" })).toMatchObject({ entries: ["sealed-bundle"] });
    await newDevice.close();
  });

  it("link-open needs auth and a 26-char b32 lid; a lid can't be opened twice", async () => {
    const anon = await TestClient.connect(r.url);
    expect(await anon.request({ t: "link-open", lid: newLid() })).toMatchObject({ code: "auth-required" });
    expect(await lc.request({ t: "link-open", lid: "TOO-SHORT" })).toMatchObject({ code: "bad-request" });
    const lid = newLid();
    expect(await lc.request({ t: "link-open", lid })).toMatchObject({ t: "ok" });
    const other = await authed(r, makeDevice(makeIdentity(), r.nowSec()));
    expect(await other.request({ t: "link-open", lid })).toMatchObject({ code: "exists" });
    await anon.close();
  });

  it("holds up to 4 req entries, in arrival order", async () => {
    const lid = newLid();
    await lc.request({ t: "link-open", lid });
    const anon = await TestClient.connect(r.url);
    for (let i = 0; i < 4; i++) expect(await anon.request({ t: "link-put", lid, slot: "req", data: `r${i}` })).toMatchObject({ t: "ok" });
    expect(await anon.request({ t: "link-put", lid, slot: "req", data: "r4" })).toMatchObject({ code: "full" });
    expect((await lc.request({ t: "link-get", lid, slot: "req" })).entries).toEqual(["r0", "r1", "r2", "r3"]);
    await anon.close();
  });

  it("accepts resp only from the connection that opened the mailbox, once", async () => {
    const lid = newLid();
    await lc.request({ t: "link-open", lid });
    const anon = await TestClient.connect(r.url);
    expect(await anon.request({ t: "link-put", lid, slot: "resp", data: "evil" })).toMatchObject({ code: "forbidden" });
    // Even another authenticated connection of the same device can't.
    const lc2 = await authed(r, linker);
    expect(await lc2.request({ t: "link-put", lid, slot: "resp", data: "evil" })).toMatchObject({ code: "forbidden" });
    expect(await lc.request({ t: "link-put", lid, slot: "resp", data: "good" })).toMatchObject({ t: "ok" });
    expect(await lc.request({ t: "link-put", lid, slot: "resp", data: "again" })).toMatchObject({ code: "full" });
    expect((await anon.request({ t: "link-get", lid, slot: "resp" })).entries).toEqual(["good"]);
    await anon.close();
  });

  it("caps each entry at 16 KiB", async () => {
    const lid = newLid();
    await lc.request({ t: "link-open", lid });
    expect(await lc.request({ t: "link-put", lid, slot: "req", data: "x".repeat(16 * 1024) })).toMatchObject({ t: "ok" });
    expect(await lc.request({ t: "link-put", lid, slot: "req", data: "x".repeat(16 * 1024 + 1) })).toMatchObject({ code: "too-large" });
  });

  it("expires after 10 minutes", async () => {
    const lid = newLid();
    await lc.request({ t: "link-open", lid });
    await lc.request({ t: "link-put", lid, slot: "req", data: "r" });
    r.clock.advance(10 * 60_000);
    expect(await lc.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ code: "not-found" });
    expect(await lc.request({ t: "link-put", lid, slot: "req", data: "r" })).toMatchObject({ code: "not-found" });
    // The lid can be opened again afterwards.
    expect(await lc.request({ t: "link-open", lid })).toMatchObject({ t: "ok" });
  });

  it("limits how many link mailboxes one device holds open", async () => {
    for (let i = 0; i < 4; i++) expect(await lc.request({ t: "link-open", lid: newLid() })).toMatchObject({ t: "ok" });
    expect(await lc.request({ t: "link-open", lid: newLid() })).toMatchObject({ code: "full" });
  });

  it("validates link-put / link-get frames", async () => {
    const anon = await TestClient.connect(r.url);
    expect(await anon.request({ t: "link-put", lid: newLid(), slot: "other", data: "x" })).toMatchObject({ code: "bad-request" });
    expect(await anon.request({ t: "link-put", lid: newLid(), slot: "req", data: 5 })).toMatchObject({ code: "bad-request" });
    expect(await anon.request({ t: "link-get", lid: "x", slot: "req" })).toMatchObject({ code: "bad-request" });
    expect(await anon.request({ t: "link-get", lid: newLid(), slot: "req" })).toMatchObject({ code: "not-found" });
    await anon.close();
  });
});

describe("link rate limits", () => {
  it("limits unauthenticated link-put/link-get per IP", async () => {
    await r.close();
    r = await startRelay({ limits: { linkOpsPerIpPerMinute: 3 } });
    linker = makeDevice(makeIdentity(), r.nowSec());
    lc = await authed(r, linker);
    const lid = newLid();
    await lc.request({ t: "link-open", lid });
    const a = await TestClient.connect(r.url);
    const b = await TestClient.connect(r.url); // same IP, other connection
    expect(await a.request({ t: "link-put", lid, slot: "req", data: "1" })).toMatchObject({ t: "ok" });
    expect(await b.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ t: "link" });
    expect(await a.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ t: "link" });
    expect(await b.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ code: "rate-limited" });
    r.clock.advance(60_000);
    expect(await b.request({ t: "link-get", lid, slot: "req" })).toMatchObject({ t: "link" });
    await a.close();
    await b.close();
  });
});
