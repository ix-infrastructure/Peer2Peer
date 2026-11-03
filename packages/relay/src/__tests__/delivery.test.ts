// Copyright 2026 Ix Infrastructure Inc.
// §5.4 store and delivery: arrival order, ack, redelivery, 7-day retention,
// mailbox caps.

import { afterEach, describe, expect, it } from "vitest";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore, type Store } from "../store.js";
import { authed, DAY, makeCap, makeDevice, makeEnvelope, makeIdentity, sleep, startRelay, type Device, type TestClient, type TestRelay } from "./helpers.js";

const stores: [string, () => Store][] = [
  ["memory", () => new MemoryStore()],
  ["sqlite", () => new SqliteStore(":memory:")],
];

for (const [name, mkStore] of stores) {
  describe(`delivery (${name} store)`, () => {
    let r: TestRelay;
    let alice: Device;
    let bob: Device;
    let ac: TestClient;
    let capJws: string;

    async function setup(limits = {}) {
      r = await startRelay({ store: mkStore(), limits });
      alice = makeDevice(makeIdentity(), r.nowSec());
      bob = makeDevice(makeIdentity(), r.nowSec());
      ac = await authed(r, alice);
      // Bob connects once so the relay knows his mailbox, then goes offline.
      const bc = await authed(r, bob);
      await bc.close();
      capJws = makeCap(bob, r.nowSec(), { sub: alice.identity.userId }).jws;
    }

    async function sendN(n: number, opts: { padTo?: number } = {}): Promise<string[]> {
      const envs: string[] = [];
      for (let i = 0; i < n; i++) {
        const env = makeEnvelope(alice, { userId: bob.identity.userId, did: bob.did }, { plaintext: `m${i}`, ...opts });
        expect(await ac.request({ t: "send", to: bob.identity.userId, tdid: bob.did, env, cap: capJws })).toMatchObject({ t: "sent" });
        envs.push(env);
      }
      return envs;
    }

    afterEach(async () => {
      await r.close();
    });

    it("delivers stored envelopes in arrival order on connect, then live ones", async () => {
      await setup();
      const envs = await sendN(5);
      const bc = await authed(r, bob);
      const got = await bc.drainEnvs();
      expect(got.map((f) => f.env)).toEqual(envs);
      const rids = got.map((f) => Number(f.rid));
      expect([...rids].sort((a, b) => a - b)).toEqual(rids);
      const live = await sendN(1);
      expect((await bc.next((f) => f.t === "env")).env).toBe(live[0]);
      await bc.close();
    });

    it("says caught-up once, after the last stored envelope, and never again on that connection", async () => {
      await setup();
      const envs = await sendN(70); // more than one delivery page
      const bc = await authed(r, bob);
      const marker = await bc.next((f) => f.t === "caught-up");
      expect(marker).toEqual({ t: "caught-up" });
      // Every stored envelope arrived before the marker (frames queue in arrival order).
      const got = bc.frames.filter((f) => f.t === "env");
      expect(got.map((f) => f.env)).toEqual(envs);
      bc.frames.length = 0;
      // A live envelope afterwards comes alone.
      const live = await sendN(1);
      expect((await bc.next((f) => f.t === "env")).env).toBe(live[0]);
      await sleep(50);
      expect(bc.frames.filter((f) => f.t === "caught-up")).toEqual([]);
      await bc.close();
      // An empty mailbox: the marker comes right after the auth reply.
      const bc2 = await authed(r, bob);
      expect(await bc2.next((f) => f.t === "caught-up")).toEqual({ t: "caught-up" });
      await bc2.close();
    });

    it("ack deletes; everything un-acked is redelivered on reconnect", async () => {
      await setup();
      const envs = await sendN(4);
      const bc = await authed(r, bob);
      const got = await bc.drainEnvs();
      expect(got).toHaveLength(4);
      bc.send({ t: "ack", rids: [got[0].rid, got[2].rid] });
      await bc.close();

      const bc2 = await authed(r, bob);
      const again = await bc2.drainEnvs();
      expect(again.map((f) => f.env)).toEqual([envs[1], envs[3]]);
      // Same rids as the first delivery.
      expect(again.map((f) => f.rid)).toEqual([got[1].rid, got[3].rid]);
      bc2.send({ t: "ack", rids: again.map((f) => f.rid) });
      await bc2.close();

      const bc3 = await authed(r, bob);
      expect(await bc3.drainEnvs()).toHaveLength(0);
      expect(r.store.counts().envelopes).toBe(0);
      await bc3.close();
    });

    it("an ack can't delete someone else's envelopes", async () => {
      await setup();
      await sendN(2);
      const bc = await authed(r, bob);
      const got = await bc.drainEnvs();
      ac.send({ t: "ack", rids: got.map((f) => f.rid) });
      await new Promise((res) => setTimeout(res, 50));
      expect(r.store.counts().envelopes).toBe(2);
      await bc.close();
    });

    it("rejects malformed acks", async () => {
      await setup();
      expect(await ac.request({ t: "ack", rids: "1" })).toMatchObject({ code: "bad-request" });
      expect(await ac.request({ t: "ack", rids: [1] })).toMatchObject({ code: "bad-request" });
      expect(await ac.request({ t: "ack", rids: ["0"] })).toMatchObject({ code: "bad-request" });
    });

    it("keeps un-acked envelopes for 7 days (fake clock)", async () => {
      await setup();
      await sendN(1);
      r.clock.advance(6 * DAY * 1000);
      // Certificates were minted at T0 and still valid; the newer envelope arrives on day 6.
      const late = await sendN(1);
      r.clock.advance(DAY * 1000 + 1000); // first envelope now 7d+1s old
      await r.relay.sweep();
      expect(r.store.counts().envelopes).toBe(1);
      const bc = await authed(r, bob);
      expect((await bc.drainEnvs()).map((f) => f.env)).toEqual(late);
      await bc.close();
    });

    it("never delivers an expired envelope even before the sweep runs", async () => {
      await setup();
      await sendN(2);
      r.clock.advance(7 * DAY * 1000 + 1);
      const bc = await authed(r, bob);
      expect(await bc.drainEnvs()).toHaveLength(0);
      await bc.close();
    });

    it("drops the oldest when a mailbox exceeds its envelope cap", async () => {
      await setup({ mailboxEnvelopes: 3 });
      const envs = await sendN(5);
      const bc = await authed(r, bob);
      expect((await bc.drainEnvs()).map((f) => f.env)).toEqual(envs.slice(2));
      await bc.close();
    });

    it("drops the oldest when a mailbox exceeds its byte cap", async () => {
      await setup({ mailboxBytes: 3 * 9000 });
      const envs = await sendN(4, { padTo: 6000 });
      const bc = await authed(r, bob);
      const got = (await bc.drainEnvs()).map((f) => f.env);
      expect(got.length).toBeLessThan(4);
      expect(got).toEqual(envs.slice(4 - got.length));
      expect(got.reduce((n, e) => n + e.length, 0)).toBeLessThanOrEqual(3 * 9000);
      await bc.close();
    });

    it("delivers to every live connection of the mailbox", async () => {
      await setup();
      const b1 = await authed(r, bob);
      const b2 = await authed(r, bob);
      const [env] = await sendN(1);
      expect((await b1.next((f) => f.t === "env")).env).toBe(env);
      expect((await b2.next((f) => f.t === "env")).env).toBe(env);
      await b1.close();
      await b2.close();
    });
  });
}
