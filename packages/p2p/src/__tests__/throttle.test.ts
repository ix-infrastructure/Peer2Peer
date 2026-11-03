// Copyright 2026 Ix Infrastructure Inc.
//
// pre-release re-review lows: the own-document refresh a refusing relay triggers is
// throttled per relay (L1), and outright publish refusals are retried at
// most hourly instead of on every connect (L2).

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { App, recordPublishOutcome, relaysToRetry } from "../app.js";
import type { SelfDoc } from "../state.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://throttle.test/v3";
let relay: TestRelay;
let u: User;

beforeAll(async () => {
  relay = await startRelay(R);
  u = new User("thr", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  await u.ok(["init", "--name", "thr", "--relay", R, "--yes"]);
});

afterAll(async () => {
  await relay?.close();
  u?.cleanup();
});

async function app(extra: Record<string, string> = {}): Promise<App> {
  const a = new App({ env: { ...u.env, ...extra }, io: { out: () => {}, err: () => {} } });
  await a.load();
  return a;
}

describe("L1: a refusing relay can't force a refresh every second", () => {
  it("refreshes at most once per relay per P2P_REFUSED_REFRESH_SEC, reusing the verdict", async () => {
    const a = await app();
    const spy = vi.spyOn(a, "refreshIdentity");
    expect(await a.authRefusedVerdict("wss://hostile.test/v3")).toBe("retry");
    expect(await a.authRefusedVerdict("wss://hostile.test/v3")).toBe("retry");
    expect(await a.authRefusedVerdict("wss://hostile.test/v3")).toBe("retry");
    expect(spy).toHaveBeenCalledTimes(1);
    await a.authRefusedVerdict("wss://other.test/v3");
    expect(spy).toHaveBeenCalledTimes(2);
    await a.close();
    const b = await app({ P2P_REFUSED_REFRESH_SEC: "0" });
    const spyB = vi.spyOn(b, "refreshIdentity");
    await b.authRefusedVerdict("wss://hostile.test/v3");
    await b.authRefusedVerdict("wss://hostile.test/v3");
    expect(spyB).toHaveBeenCalledTimes(2);
    await b.close();
  });
});

describe("L2: outright publish refusals back off", () => {
  const base: SelfDoc = { name: "x", relays: ["a", "b", "c", "d"], createdAt: 0 };

  it("classifies transient failures for every-connect retry, refusals with a timestamp", () => {
    const s = recordPublishOutcome(base, ["d"], [
      { relay: "a", code: "network" },
      { relay: "b", code: "forbidden" },
      { relay: "c", code: "identity-gap" },
    ], 1_000);
    expect(s.unpublished).toEqual(["a", "c"]);
    expect(s.refusedPublish).toEqual({ b: 1_000 });
    // A later success clears a refusal.
    expect(recordPublishOutcome(s, ["b"], [], 2_000).refusedPublish).toBeUndefined();
    expect(relaysToRetry(s, 1_000 + 60_000, 3_600_000)).toEqual(["a", "c"]);
    expect(relaysToRetry(s, 1_000 + 3_600_000, 3_600_000).sort()).toEqual(["a", "b", "c"]);
  });

  it("a `forbidden` relay isn't retried on the next connects within the hour; a network failure is", async () => {
    const a = await app();
    // Stand-in pool: one relay refuses outright, one is unreachable.
    const calls: string[] = [];
    (a as unknown as { pool: unknown }).pool = {
      publishIdentity: async (r: string) => {
        calls.push(r);
        if (r === "wss://refuses.test/v3") return "forbidden";
        throw Object.assign(new Error("down"), { code: "network" });
      },
      drain: async () => {},
      close: () => {},
    };
    const head = (await a.ownView()).head.jws;
    await a.publishDoc(head, ["wss://refuses.test/v3", "wss://down.test/v3"]);
    expect(a.self!.unpublished).toEqual(["wss://down.test/v3"]);
    expect(Object.keys(a.self!.refusedPublish ?? {})).toEqual(["wss://refuses.test/v3"]);
    calls.length = 0;
    await a.retryUnpublished();
    expect(calls).toEqual(["wss://down.test/v3"]);
    // Past the backoff, the refusing relay is tried again.
    const later = await app({ P2P_REFUSED_PUBLISH_RETRY_SEC: "0" });
    (later as unknown as { pool: unknown }).pool = (a as unknown as { pool: unknown }).pool;
    calls.length = 0;
    await later.retryUnpublished();
    expect(calls.sort()).toEqual(["wss://down.test/v3", "wss://refuses.test/v3"]);
    (a as unknown as { pool: unknown }).pool = undefined;
    (later as unknown as { pool: unknown }).pool = undefined;
  });
});
