// Copyright 2026 Ix Infrastructure Inc.
//
// A send by the person at their terminal (`p2p send` with no --from-session, `p2p tui`) shares the
// `tui` session with its recipient first (sessions.ts sendSharing), and takes the share back when
// the send fails. Issue #3: taken back only when nothing can have gone out (a relay may hold a copy
// whose answer never came: their reply must still land), and only while the roster is still exactly
// the version the share wrote (a change made meanwhile stands).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { App } from "../app.js";
import { roster, sendSharing } from "../sessions.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-send-sharing.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
const ids: Record<string, string> = {};

type SendEnvelope = NonNullable<App["pool"]>["sendEnvelope"];

const parts = async (sid: string): Promise<string[]> => ((await ann.ok(["session", "roster", sid])).roster.parts as { userId: string }[]).map((p) => p.userId);

/**
 * One sendSharing from Ann's terminal session (`tui`, shared with nobody first) to Ben, with every
 * copy to Ben answered by `fail`; `shared`: whether the session was shared with Ben while it went out.
 */
async function failedSend(fail: (...a: Parameters<SendEnvelope>) => ReturnType<SendEnvelope>): Promise<{ e: unknown; shared: boolean }> {
  await ann.ok(["session", "roster", "tui", "--remove", ids.ben]);
  expect(await parts("tui")).not.toContain(ids.ben);
  const app = await ann.app();
  await app.load();
  await app.connect();
  const pool = app.pool!;
  const real = pool.sendEnvelope.bind(pool);
  let shared = false;
  pool.sendEnvelope = async (env, to, tdid, kind, targets) => {
    if (kind !== "msg" || to !== ids.ben) return real(env, to, tdid, kind, targets);
    shared = (await parts("tui")).includes(ids.ben);
    return fail(env, to, tdid, kind, targets);
  };
  try {
    await sendSharing(app, { fromSession: "tui", to: ids.ben, text: "hello" });
    return { e: undefined, shared };
  } catch (e) {
    return { e, shared };
  } finally {
    await app.close();
  }
}

describe("the share a terminal send makes, when the send fails (issue #3)", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    for (const u of [ann, ben]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    const code = (await ann.ok(["invite"])).code as string;
    await ben.ok(["join", "--confirmed", code]);
    await ann.ok(["friends"]);
  }, 90_000);

  afterAll(async () => {
    await relay?.close();
    ann?.cleanup();
    ben?.cleanup();
  });

  it("nothing went out (refused before a byte was written): the share is taken back", async () => {
    const { e, shared } = await failedSend(async (_e, _t, _d, _k, targets) => ({ sent: [], errors: targets.map((x) => ({ relay: x.relay, code: "forbidden" })) }));
    expect(e).toMatchObject({ code: "undelivered" });
    expect(shared).toBe(true);
    expect(await parts("tui")).not.toContain(ids.ben);
  }, 60_000);

  it("a copy went out and its answer never came (a relay may hold it): the share stays", async () => {
    const { e, shared } = await failedSend(async (_e, _t, _d, _k, targets) => ({ sent: [], errors: targets.map((x) => ({ relay: x.relay, code: "forbidden", written: true })) }));
    expect(e).toMatchObject({ code: "undelivered" });
    expect(shared).toBe(true);
    expect(await parts("tui")).toContain(ids.ben);
  }, 60_000);

  it("the roster changed after the share (here: the person shared it with Ben themselves): left as it is", async () => {
    const { e, shared } = await failedSend(async (_e, _t, _d, _k, targets) => {
      const other = await ann.app();
      await other.load();
      try {
        await roster(other, "tui", { add: [ids.ben] });
      } finally {
        await other.close();
      }
      return { sent: [], errors: targets.map((x) => ({ relay: x.relay, code: "forbidden" })) };
    });
    expect(e).toMatchObject({ code: "undelivered" });
    expect(shared).toBe(true);
    expect(await parts("tui")).toContain(ids.ben);
  }, 60_000);
});
