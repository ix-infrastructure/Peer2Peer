// Copyright 2026 Ix Infrastructure Inc.
//
// pre-release third re-review, client side: restore updates a lagging relay (R3-M2),
// the post-merge re-add fails closed on partial history (R3-M3), a block
// stays effective through circle bundles (R3-L1), and CLI merges don't trip
// compromise detection (R3-L2).

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createIdentityDoc,
  detectUnpublishedVersion,
  generateDeviceKeysV3,
  generateIdentityKey,
  IdentityChain,
  mergeFields,
  peekIdentityDoc,
  verifyIdentityDocSignature,
} from "@peer2peer/core/v3";
import { branchesCovered, planReadd } from "../app.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://r3-one.test/v3";
const R2 = "wss://r3-two.test/v3";
let r1: TestRelay;
let r2: TestRelay;
let t: Record<string, string>;
const users: User[] = [];
const ids: Record<string, string> = {};

function user(name: string, transport = t): User {
  const u = new User(name, transport);
  users.push(u);
  return u;
}

beforeAll(async () => {
  r1 = await startRelay(R1);
  r2 = await startRelay(R2);
  t = { [R1]: `ws://127.0.0.1:${r1.port}/v3`, [R2]: `ws://127.0.0.1:${r2.port}/v3` };
});

afterAll(async () => {
  await r1?.close();
  await r2?.close();
  for (const u of users) u.cleanup();
});

describe("R3-M2: restore with one relay behind", () => {
  it("back-fills the lagging relay, which ends up holding the restored version", async () => {
    const owner = user("lag");
    ids.lag = (await owner.ok(["init", "--name", "lag", "--relay", R1, "--relay", R2, "--yes"])).userId;
    // Two versions published while R2 is unreachable: R2 stays at version 1.
    const offR2 = new User("lag-off", { [R1]: t[R1], [R2]: "ws://127.0.0.1:9/v3" }, { P2P_HOME: owner.home });
    await offR2.ok(["profile", "set", "--bio", "one"]);
    await offR2.ok(["profile", "set", "--bio", "two"]);
    expect(r2.relay.identity.head(ids.lag)?.jws && peekIdentityDoc(r2.relay.identity.head(ids.lag)!.jws).ver).toBe(1);
    const phrase = (await owner.ok(["backup", "show"])).phrase as string;
    const fresh = user("lag-restored");
    const r = await fresh.ok(["backup", "restore", "--relay", R1, "--relay", R2], { stdin: phrase });
    expect(r.failed).toEqual([]);
    expect(r.ver).toBe(4);
    expect(peekIdentityDoc(r2.relay.identity.head(ids.lag)!.jws).ver).toBe(4);
    expect(peekIdentityDoc(r1.relay.identity.head(ids.lag)!.jws).ver).toBe(4);
  });
});

describe("R3-M3: re-adding after a merge fails closed on partial history", () => {
  it("re-adds only when the held history covers each branch back to the common ancestor", () => {
    const ik = generateIdentityKey();
    const k = generateDeviceKeysV3(ik.userId);
    const n = generateDeviceKeysV3(ik.userId);
    const base = { name: "pp", relays: [R1], keyholders: [k.did], by: k.did };
    const v1 = createIdentityDoc(ik, { ...base, ver: 1, prev: null, devices: [k.did, n.did] });
    const h = (j: string) => peekIdentityDoc(j).hash;
    // Branch b revokes N (b2) and goes on (b3); branch a keeps N.
    const b2 = createIdentityDoc(ik, { ...base, ver: 2, prev: h(v1), devices: [k.did], name: "pp" });
    const b3 = createIdentityDoc(ik, { ...base, ver: 3, prev: h(b2), devices: [k.did], name: "pp" });
    const a2 = createIdentityDoc(ik, { ...base, ver: 2, prev: h(v1), devices: [k.did, n.did], name: "pp" });
    const f = mergeFields(verifyIdentityDocSignature(a2), verifyIdentityDocSignature(b3));
    const m = createIdentityDoc(ik, { ...f, by: k.did });
    const full = IdentityChain.fromStored({ iss: ik.userId, versions: [v1, b2, b3, a2, m] });
    expect(branchesCovered(full, [h(a2), h(b3)])).toBe(true);
    // Full history: N was revoked along b, so it is not re-added.
    expect(planReadd(full, [h(a2), h(b3)], [k.did, n.did], [k.did], h(m), [])).toEqual({ readd: [], skipped: [] });
    // Partial history (b2 missing): N looks merge-dropped only, but this copy can't prove it.
    const partial = IdentityChain.fromStored({ iss: ik.userId, versions: [v1, b3, a2, m] });
    expect(branchesCovered(partial, [h(a2), h(b3)])).toBe(false);
    expect(planReadd(partial, [h(a2), h(b3)], [k.did, n.did], [k.did], h(m), [])).toEqual({ readd: [], skipped: [n.did] });
  });
});

describe("R3-L1: a block survives circle bundles", () => {
  it("the owner's distributions never hand the blocked member our new join statement", async () => {
    const a = user("l1a", { [R1]: t[R1] });
    ids.l1a = (await a.ok(["init", "--name", "l1a", "--relay", R1, "--yes"])).userId;
    const b = user("l1b", { [R1]: t[R1] });
    ids.l1b = (await b.ok(["init", "--name", "l1b", "--relay", R1, "--yes"])).userId;
    const circle = await a.ok(["circle", "create", "l1", "--open"]);
    const lnk = (await a.ok(["circle", "invite", circle.cid, "--link"])).link as string;
    await b.ok(["circle", "join", lnk, "--wait", "0"]);
    await a.ok(["circle", "ls"]);
    await b.ok(["circle", "join", lnk, "--wait", "3"]);
    await a.ok(["circle", "ls"]);
    await b.ok(["circle", "ls"]);
    await a.ok(["circle", "default", circle.cid]);
    await a.ok(["status", "--session", "as", "--state", "busy"]);
    await a.ok(["block", ids.l1b]);
    // The owner publishes again (distributing the chain and statements to every member).
    await a.ok(["circle", "propose", circle.cid, "rename", "l1-renamed"]);
    await b.ok(["circle", "ls"]);
    // b's project is shared with the circle: what stops this is the block, not b's own boundary (projects.ts).
    await b.share(circle.cid);
    const sent = await b.run(["send", "--from-session", "bs", "--to", `${ids.l1a}/as`, "still?"]);
    expect(sent.code).toBe(1);
    expect(sent.json.error).toBe("undelivered");
  });
});

describe("R3-L2: CLI merges and compromise detection", () => {
  it("a merge `by` another key holder, a pure intersection, doesn't alert that device's detector", () => {
    const ik = generateIdentityKey();
    const k1 = generateDeviceKeysV3(ik.userId);
    const k2 = generateDeviceKeysV3(ik.userId);
    const n = generateDeviceKeysV3(ik.userId);
    const base = { name: "ld", relays: [R1], keyholders: [k1.did, k2.did] };
    const h = (j: string) => peekIdentityDoc(j).hash;
    const v1 = createIdentityDoc(ik, { ...base, ver: 1, prev: null, devices: [k1.did, k2.did], by: k1.did });
    const a = createIdentityDoc(ik, { ...base, ver: 2, prev: h(v1), devices: [k1.did, k2.did, n.did], by: k1.did });
    const b = createIdentityDoc(ik, { ...base, ver: 2, prev: h(v1), devices: [k1.did, k2.did], by: k2.did, name: "ld" });
    const A = verifyIdentityDocSignature(a);
    const B = verifyIdentityDocSignature(b);
    // A restoring or third device writes the merge naming k1 (the lowest common key holder) as `by`.
    const merge = verifyIdentityDocSignature(createIdentityDoc(ik, { ...mergeFields(A, B), by: [k1.did, k2.did].sort()[0] }));
    // k2's own log knows only b; the merge adds nothing, so no alert.
    const k2Log = { published: [B.hash], addedDevices: [], addedRelays: [], addedProofs: [] };
    expect(detectUnpublishedVersion(merge, [A, B], k2Log, [k1.did, k2.did]).alert).toBe(false);
  });
});
