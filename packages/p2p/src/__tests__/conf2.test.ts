// Copyright 2026 Ix Infrastructure Inc.
//
// review N-C: a second confirmer whose want didn't go out (marked due to be asked again) is asked
// again on the next try, like the first confirmers; it used to be skipped for good.

import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { App } from "../app.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-conf2.test/v3";
let relay: TestRelay;
const users: User[] = [];
const ids: Record<string, string> = {};

async function user(name: string): Promise<User> {
  const u = new User(name, { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  users.push(u);
  ids[name] = (await u.ok(["init", "--name", name, "--relay", R, "--yes"])).userId;
  return u;
}

beforeAll(async () => {
  relay = await startRelay(R);
});

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await relay?.close();
  for (const u of users) u.cleanup();
});

describe("the second confirmer (N-C)", () => {
  it("is asked again after its want failed", async () => {
    const o = await user("c2own");
    const m = await user("c2mem");
    const j = await user("c2join");
    const cid = (await o.ok(["circle", "create", "grow", "--open"])).cid as string;
    // An old link (its head lists only the owner); then a member joins, so the owner's answer is
    // newer than the link and names a second member to confirm with.
    const oldLink = (await o.ok(["circle", "invite", cid, "--link"])).link as string;
    await m.ok(["circle", "join", oldLink, "--wait", "0"]);
    await o.ok(["circle", "ls"]);
    expect((await m.ok(["circle", "join", oldLink, "--wait", "4"])).status).toBe("joined");
    await o.ok(["circle", "ls"]);
    // The joiner's wants to that member: the first one reaches no relay.
    const deliver = App.prototype.deliver;
    let asks = 0;
    vi.spyOn(App.prototype, "deliver").mockImplementation(async function (this: App, ...args: Parameters<App["deliver"]>) {
      const pt = args[3] as { want?: unknown };
      if (this.userId === ids.c2join && args[0] === ids.c2mem && args[1] === "circle" && pt.want) {
        asks++;
        if (asks === 1) return { userId: args[0], devices: 1, relays: [] };
      }
      return deliver.apply(this, args);
    });
    await alongside(j.run(["circle", "join", oldLink, "--wait", "3"]), () => o.run(["invites"]));
    expect(asks).toBe(1);
    await alongside(j.run(["circle", "join", oldLink, "--wait", "3"]), () => o.run(["invites"]));
    expect(asks).toBe(2);
  }, 90_000);
});
