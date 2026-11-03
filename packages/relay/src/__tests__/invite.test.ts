// Copyright 2026 Ix Infrastructure Inc.
// P4 short-code invite mailboxes (docs/protocol.md "P4. Short-code invites").

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { randomBytes } from "@peer2peer/core";
import { b32Encode } from "../crypto.js";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore } from "../store.js";
import { authed, DAY, makeDevice, makeDoc, makeIdentity, startRelay, TestClient, type Device, type TestRelay } from "./helpers.js";
import type { RelayLimits } from "../config.js";

const newLid = () => b32Encode(randomBytes(20)).slice(0, 26);
let r: TestRelay | undefined;
const clients: TestClient[] = [];
const dirs: string[] = [];

afterEach(async () => {
  for (const c of clients.splice(0)) await c.close().catch(() => 0);
  await r?.close();
  r = undefined;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

async function setup(limits: Partial<RelayLimits> = {}, store?: SqliteStore) {
  r = await startRelay({ limits: { inviteGetsPerIpPerMinute: 1000, inviteMissesPerIpPerHour: 1000, ...limits }, ...(store ? { store } : {}) });
  const id = makeIdentity();
  const owner = await authed(r, makeDevice(id, r.nowSec()));
  const anon = await TestClient.connect(r.url);
  clients.push(owner, anon);
  return { r, owner, anon, id };
}

describe("invite mailboxes", () => {
  it("an authenticated put; anyone takes it exactly once, without authenticating", async () => {
    const { owner, anon } = await setup();
    const lid = newLid();
    expect(await owner.request({ t: "invite-put", lid, blob: "sealed", ttl: 3600 })).toMatchObject({ t: "ok", exp: r!.nowSec() + 3600 });
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ t: "invite", lid, blob: "sealed" });
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ t: "error", code: "not-found" });
    // Not even the owner gets it back.
    expect(await owner.request({ t: "invite-get", lid })).toMatchObject({ code: "not-found" });
  });

  it("put needs auth and a 26-char b32 lid; a lid is never overwritten (no swapping a blob)", async () => {
    const { owner, anon } = await setup();
    const lid = newLid();
    expect(await anon.request({ t: "invite-put", lid, blob: "x", ttl: 60 })).toMatchObject({ code: "auth-required" });
    expect(await owner.request({ t: "invite-put", lid: "NOT-A-LID", blob: "x", ttl: 60 })).toMatchObject({ code: "bad-request" });
    expect(await owner.request({ t: "invite-put", lid, blob: "x" })).toMatchObject({ code: "bad-request" });
    expect(await owner.request({ t: "invite-put", lid, blob: "first", ttl: 60 })).toMatchObject({ t: "ok" });
    const other = await authed(r!, makeDevice(makeIdentity(), r!.nowSec()));
    clients.push(other);
    expect(await other.request({ t: "invite-put", lid, blob: "evil", ttl: 60 })).toMatchObject({ code: "exists" });
    expect(await owner.request({ t: "invite-put", lid, blob: "again", ttl: 60 })).toMatchObject({ code: "exists" });
    expect((await anon.request({ t: "invite-get", lid })).blob).toBe("first");
  });

  it("caps a blob at 32 KiB", async () => {
    const { owner } = await setup();
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "x".repeat(32 * 1024), ttl: 60 })).toMatchObject({ t: "ok" });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "x".repeat(32 * 1024 + 1), ttl: 60 })).toMatchObject({ code: "too-large" });
  });

  it("clamps the TTL to 7 days; an expired invite is gone, and swept", async () => {
    const { owner, anon } = await setup();
    const lid = newLid();
    const lid2 = newLid();
    expect(await owner.request({ t: "invite-put", lid, blob: "b", ttl: 30 * DAY })).toMatchObject({ exp: r!.nowSec() + 7 * DAY });
    expect(await owner.request({ t: "invite-put", lid: lid2, blob: "b", ttl: 60 })).toMatchObject({ t: "ok" });
    r!.clock.advance(61_000);
    expect(await anon.request({ t: "invite-get", lid: lid2 })).toMatchObject({ code: "not-found" });
    r!.clock.advance(7 * DAY * 1000);
    expect(r!.store.inviteBytes()).toBe(1);
    await r!.relay.sweep();
    expect(r!.store.inviteBytes()).toBe(0);
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ code: "not-found" });
  });

  it("bounds open invites per user, and puts per user per hour", async () => {
    const { owner } = await setup({ inviteOpenPerIss: 2, invitePutPerIssPerHour: 4 });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 60 })).toMatchObject({ t: "ok" });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 60 })).toMatchObject({ t: "ok" });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 60 })).toMatchObject({ code: "full" });
    // Expired ones don't count against the open cap.
    r!.clock.advance(61_000);
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 60 })).toMatchObject({ t: "ok" });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "b", ttl: 60 })).toMatchObject({ code: "rate-limited" });
  });

  it("bounds the bytes held across every invite", async () => {
    const { owner } = await setup({ inviteTotalBytes: 100 });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "x".repeat(80), ttl: 60 })).toMatchObject({ t: "ok" });
    expect(await owner.request({ t: "invite-put", lid: newLid(), blob: "x".repeat(30), ttl: 60 })).toMatchObject({ code: "full" });
  });

  describe("M2: one network can't fill the store for everyone", () => {
    async function from(ip: string, d: Device = makeDevice(makeIdentity(), r!.nowSec())): Promise<TestClient> {
      const c = await TestClient.connect(r!.url, { "x-forwarded-for": ip });
      clients.push(c);
      d.cert = makeDevice(d.identity, r!.nowSec(), {}, d.spkSecret).cert;
      const ok = await c.auth(d);
      if (ok.t !== "ok") throw new Error(JSON.stringify(ok));
      return c;
    }
    /** A device whose identity document the relay holds from now on. */
    async function established(ip: string): Promise<Device> {
      const id = makeIdentity();
      const d = makeDevice(id, r!.nowSec());
      const c = await from(ip, d);
      expect(await c.request({ t: "identity", doc: makeDoc(id, r!.nowSec(), { devices: [d.did] }).jws })).toMatchObject({ t: "ok" });
      return d;
    }
    const put = (c: TestClient, n: number) => c.request({ t: "invite-put", lid: newLid(), blob: "x".repeat(n), ttl: 3600 });

    it("caps open invite bytes per source network, IPv6 counted per /48", async () => {
      r = await startRelay({ config: { trustProxy: 1 }, limits: { inviteBytesPerIp: 100 } });
      expect(await put(await from("2001:db8:1:aaaa::1"), 80)).toMatchObject({ t: "ok" });
      // Another identity, another /64 of the same /48: same budget.
      expect(await put(await from("2001:db8:1:bbbb::1"), 30)).toMatchObject({ code: "full" });
      expect(await put(await from("2001:db8:2:aaaa::1"), 30)).toMatchObject({ t: "ok" });
      expect(await put(await from("198.51.100.7"), 100)).toMatchObject({ t: "ok" });
      expect(await put(await from("198.51.100.7"), 1)).toMatchObject({ code: "full" });
    });

    it("past 90% only identities older than a day may put; when full, the biggest holders' newest invites go", async () => {
      r = await startRelay({ config: { trustProxy: 1 }, limits: { inviteTotalBytes: 1000, inviteBytesPerIp: 10_000 } });
      const hd = await established("198.51.100.1");
      const fd = await established("203.0.113.9");
      const ld = await established("192.0.2.60");
      r.clock.advance(2 * DAY * 1000);
      const honest = await from("198.51.100.1", hd);
      const flooder = await from("203.0.113.9", fd);
      const honestLid = newLid();
      expect(await honest.request({ t: "invite-put", lid: honestLid, blob: "h".repeat(100), ttl: 7 * DAY })).toMatchObject({ t: "ok" });
      const floodLids: string[] = [];
      for (let i = 0; i < 8; i++) {
        const lid = newLid();
        floodLids.push(lid);
        r.clock.advance(1000);
        expect(await flooder.request({ t: "invite-put", lid, blob: "f".repeat(100), ttl: 7 * DAY })).toMatchObject({ t: "ok" });
      }
      // 900 of 1000 bytes held: a brand-new identity is refused, an established one isn't.
      expect(await put(await from("192.0.2.50"), 50)).toMatchObject({ code: "full" });
      const late = await from("192.0.2.60", ld);
      expect(await put(late, 100)).toMatchObject({ t: "ok" });
      // Full now: the next put evicts the flooder's newest invite, not the honest one.
      expect(await put(late, 100)).toMatchObject({ t: "ok" });
      const anon = await TestClient.connect(r.url, { "x-forwarded-for": "192.0.2.99" });
      clients.push(anon);
      expect(await anon.request({ t: "invite-get", lid: floodLids[7] })).toMatchObject({ code: "not-found" });
      expect(await anon.request({ t: "invite-get", lid: floodLids[0] })).toMatchObject({ t: "invite" });
      expect(await anon.request({ t: "invite-get", lid: honestLid })).toMatchObject({ t: "invite" });
      expect(r.store.inviteBytes()).toBeLessThanOrEqual(1000);
      // L2: the flooder's list says which of its codes were evicted (not "taken").
      expect(await flooder.request({ t: "invite-list" })).toMatchObject({ evicted: [floodLids[7]] });
      expect((await honest.request({ t: "invite-list" })).evicted).toEqual([]);
    });
  });

  describe("per-userId invite byte totals and evicted tombstones (both stores)", () => {
    const stores = {
      memory: () => new MemoryStore(),
      sqlite: () => {
        const dir = mkdtempSync(join(tmpdir(), "relay-inv-tot-"));
        dirs.push(dir);
        return new SqliteStore(join(dir, "relay.db"));
      },
    };
    for (const [name, make] of Object.entries(stores)) {
      it(`${name}: totals follow every write; eviction takes the biggest holder's newest and leaves a tombstone until expiry`, () => {
        const st = make();
        const inv = (lid: string, iss: string, size: number, at: number) => ({ lid, iss, blob: "x".repeat(size), size, createdAt: at, expiresAt: 10_000, src: "s" });
        st.putInvite(inv("a1", "A", 100, 1));
        st.putInvite(inv("a2", "A", 100, 2));
        st.putInvite(inv("a3", "A", 100, 3));
        st.putInvite(inv("b1", "B", 150, 4));
        expect([st.inviteBytesOfIss("A"), st.inviteBytesOfIss("B")]).toEqual([300, 150]);
        st.takeInvite("a1", 0);
        expect(st.deleteInvite("b1", "A")).toBe(false);
        expect(st.inviteBytesOfIss("A")).toBe(200);
        // A holds 200, B 150: A loses its newest (a3), then B (now the biggest at 150) loses b1.
        expect(st.evictInvites(120)).toBe(250);
        expect(st.evictedInvitesOf("A", 0)).toEqual(["a3"]);
        expect(st.evictedInvitesOf("B", 0)).toEqual(["b1"]);
        expect([st.inviteBytesOfIss("A"), st.inviteBytesOfIss("B"), st.inviteBytes()]).toEqual([100, 0, 100]);
        st.sweepInvites(10_000, 1000);
        expect([st.inviteBytesOfIss("A"), st.inviteBytes()]).toEqual([0, 0]);
        expect(st.evictedInvitesOf("A", 0)).toEqual([]);
        st.close();
      });
    }

    it("sqlite: the totals are rebuilt when the store is opened", () => {
      const dir = mkdtempSync(join(tmpdir(), "relay-inv-reopen-"));
      dirs.push(dir);
      const path = join(dir, "relay.db");
      const a = new SqliteStore(path);
      a.putInvite({ lid: "x1", iss: "X", blob: "b", size: 7, createdAt: 1, expiresAt: 9e12, src: "s" });
      a.close();
      const b = new SqliteStore(path);
      expect(b.inviteBytesOfIss("X")).toBe(7);
      b.close();
    });
  });

  it("only the putting user lists or deletes its invites", async () => {
    const { owner, anon, id } = await setup();
    const a = newLid();
    const b = newLid();
    await owner.request({ t: "invite-put", lid: a, blob: "b", ttl: 60 });
    await owner.request({ t: "invite-put", lid: b, blob: "b", ttl: 60 });
    // Another device of the same user sees them too.
    const sibling = await authed(r!, makeDevice(id, r!.nowSec()));
    const stranger = await authed(r!, makeDevice(makeIdentity(), r!.nowSec()));
    clients.push(sibling, stranger);
    expect([...(await sibling.request({ t: "invite-list" })).lids].sort()).toEqual([a, b].sort());
    expect((await stranger.request({ t: "invite-list" })).lids).toEqual([]);
    expect(await anon.request({ t: "invite-list" })).toMatchObject({ code: "auth-required" });
    expect(await stranger.request({ t: "invite-del", lid: a })).toMatchObject({ code: "not-found" });
    expect(await anon.request({ t: "invite-del", lid: a })).toMatchObject({ code: "auth-required" });
    expect(await sibling.request({ t: "invite-del", lid: a })).toMatchObject({ t: "ok" });
    expect(await anon.request({ t: "invite-get", lid: a })).toMatchObject({ code: "not-found" });
    expect((await owner.request({ t: "invite-list" })).lids).toEqual([b]);
  });

  it("limits invite-get per IP, and misses much harder: guessing a 100-bit code is hopeless", async () => {
    const { owner, anon } = await setup({ inviteGetsPerIpPerMinute: 10, inviteMissesPerIpPerHour: 5 });
    const lid = newLid();
    await owner.request({ t: "invite-put", lid, blob: "b", ttl: 3600 });
    // A guesser: 5 misses, then every get from the IP is refused, even the right lid.
    for (let i = 0; i < 5; i++) expect(await anon.request({ t: "invite-get", lid: newLid() })).toMatchObject({ code: "not-found" });
    expect(await anon.request({ t: "invite-get", lid: newLid() })).toMatchObject({ code: "rate-limited" });
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ code: "rate-limited" });
    // The per-minute budget refills, the miss budget doesn't (it refills over the hour).
    r!.clock.advance(60_000);
    expect(await anon.request({ t: "invite-get", lid: newLid() })).toMatchObject({ code: "rate-limited" });
    r!.clock.advance(15 * 60_000);
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ t: "invite" });
    // At the default 30 misses per IP per hour, a million IP buckets guessing for a week against
    // 10^6 open codes find one with probability 30 * 24 * 7 * 10^6 * 10^6 / 2^100 < 1e-14.
    expect((30 * 24 * 7 * 1e6 * 1e6) / 2 ** 100).toBeLessThan(1e-14);
  });

  it("a hit also spends the per-minute budget", async () => {
    const { owner, anon } = await setup({ inviteGetsPerIpPerMinute: 2 });
    const lids = [newLid(), newLid(), newLid()];
    for (const lid of lids) await owner.request({ t: "invite-put", lid, blob: "b", ttl: 3600 });
    expect(await anon.request({ t: "invite-get", lid: lids[0] })).toMatchObject({ t: "invite" });
    expect(await anon.request({ t: "invite-get", lid: lids[1] })).toMatchObject({ t: "invite" });
    expect(await anon.request({ t: "invite-get", lid: lids[2] })).toMatchObject({ code: "rate-limited" });
  });

  it("survives a restart on SQLite, still single-use", async () => {
    const dir = mkdtempSync(join(tmpdir(), "relay-inv-"));
    dirs.push(dir);
    const path = join(dir, "relay.db");
    const { owner } = await setup({}, new SqliteStore(path));
    const lid = newLid();
    await owner.request({ t: "invite-put", lid, blob: "persisted", ttl: 3600 });
    const clock = r!.clock;
    for (const c of clients.splice(0)) await c.close();
    await r!.close();
    r = await startRelay({ store: new SqliteStore(path), clock, limits: { inviteGetsPerIpPerMinute: 1000 } });
    expect(r.store.inviteBytes()).toBe("persisted".length);
    const anon = await TestClient.connect(r.url);
    clients.push(anon);
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ blob: "persisted" });
    expect(await anon.request({ t: "invite-get", lid })).toMatchObject({ code: "not-found" });
    expect(r.store.inviteBytes()).toBe(0);
  });
});
