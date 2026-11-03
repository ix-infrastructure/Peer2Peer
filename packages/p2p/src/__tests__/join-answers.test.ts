// Copyright 2026 Ix Infrastructure Inc.
//
// Review M4: what a joiner stores of each confirmer's answer is bounded and
// filtered, and a part rewrites only its sender's document (never the joins
// index).

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { CircleChain, createCircle, createNextCircleVersion, generateIdentityKey, parseCircleVersion, type IdentityKey } from "@peer2peer/core/v3";
import type { App } from "../app.js";
import { ANSWERS_PER_ASKER_PER_HOUR, contiguousTop, joinCircle, recordJoinAnswer } from "../circle-ops.js";
import { ANSWER_MAX_BYTES, answerByteCap, answerDocName, MAX_NEW_ANSWERS_PER_HOUR, MAX_PART_RECORDS, MAX_VERSIONS_PER_VER, maxVerFor, readAnswer } from "../join-answers.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-join-answers.test/v3";
let relay: TestRelay;
let u: User;
let app: App;
let ik: IdentityKey;
let chain: string[] = [];
let cid = "";

function grow(n: number): string[] {
  const out = [createCircle(ik, { name: "c", policy: "open" })];
  for (let i = 1; i < n; i++) {
    const c = CircleChain.bootstrap(out);
    out.push(createNextCircleVersion(ik, c.head, { name: `v${i + 1}` }));
  }
  return out;
}

beforeAll(async () => {
  relay = await startRelay(R);
  u = new User("ja", { [R]: `ws://127.0.0.1:${relay.port}/v3` });
  await u.ok(["init", "--name", "ja", "--relay", R, "--yes"]);
  app = await u.app();
  await app.load();
  ik = generateIdentityKey();
  chain = grow(6);
  cid = parseCircleVersion(chain[0]).cid;
  // A pending join offered version 5; the owner was asked.
  await app.state.put("joins", { [cid]: { cid, head: chain[4], joins: [], asked: [ik.userId], askedAt: Date.now() } });
}, 30_000);

afterAll(async () => {
  await app?.close();
  await relay?.close();
  u?.cleanup();
});

describe("joiner-side answer storage (M4)", () => {
  it("one document per confirmer: parts rewrite it, not the joins index", async () => {
    const writes: string[] = [];
    const orig = app.state.backend.write.bind(app.state.backend);
    const spy = vi.spyOn(app.state.backend, "write").mockImplementation(async (name: string, v: unknown) => {
      writes.push(name);
      return orig(name, v);
    });
    for (let i = 0; i < 5; i++) expect(await recordJoinAnswer(app, ik.userId, [chain[i]], [], { part: { id: "answer-0001", i: i + 1, n: 5 } })).toBe(true);
    spy.mockRestore();
    expect(writes.filter((w) => w === "joins").length).toBe(1);
    expect(writes.filter((w) => w === answerDocName(cid, ik.userId)).length).toBe(5);
    const d = await readAnswer(app, cid, ik.userId);
    expect(d!.versions.length).toBe(5);
    expect(d!.parts["answer-0001"]).toMatchObject({ n: 5, top: 5 });
  });

  it("N5: a part that adds nothing writes nothing", async () => {
    const part = { id: "answer-n5n5", i: 1, n: 1 };
    await recordJoinAnswer(app, ik.userId, [chain[0]], [], { part });
    const writes: string[] = [];
    const orig = app.state.backend.write.bind(app.state.backend);
    const spy = vi.spyOn(app.state.backend, "write").mockImplementation(async (name: string, v: unknown) => {
      writes.push(name);
      return orig(name, v);
    });
    // The same part again, and versions already held: nothing new.
    await recordJoinAnswer(app, ik.userId, [chain[0]], [], { part });
    await recordJoinAnswer(app, ik.userId, [chain[0], chain[1]], [], { cid });
    spy.mockRestore();
    expect(writes).toEqual([]);
  });

  it("drops what isn't this circle's, oversized items, and a third sibling of one ver", async () => {
    const other = createCircle(generateIdentityKey(), { name: "other" });
    const c3 = CircleChain.bootstrap(chain.slice(0, 2));
    const sibA = createNextCircleVersion(ik, c3.head, { name: "sib-a" });
    const sibB = createNextCircleVersion(ik, c3.head, { name: "sib-b" });
    await recordJoinAnswer(app, ik.userId, [other, sibA, sibB, "x".repeat(20_000)], ["y".repeat(20_000)], { cid });
    const d = await readAnswer(app, cid, ik.userId);
    expect(d!.versions).not.toContain(other);
    expect(d!.versions.filter((v) => parseCircleVersion(v).ver === 3).length).toBe(MAX_VERSIONS_PER_VER);
    expect(d!.joins).toEqual([]);
    expect(d!.bytes).toBe(d!.versions.reduce((n, v) => n + v.length, 0));
  });

  it("F4: new answers from one confirmer are rate-limited; parts of tracked ones always count", async () => {
    for (let i = 0; i < MAX_PART_RECORDS + 5; i++) await recordJoinAnswer(app, ik.userId, [chain[0]], [], { part: { id: `answer-${String(i).padStart(4, "0")}`, i: 1, n: 2 } });
    const d = await readAnswer(app, cid, ik.userId);
    const recent = Object.values(d!.parts).filter((r) => r.at !== undefined && Date.now() - r.at < 3_600_000);
    expect(recent.length).toBe(MAX_NEW_ANSWERS_PER_HOUR);
    expect(Object.keys(d!.parts).length).toBeLessThanOrEqual(MAX_PART_RECORDS);
    // A part of an answer already tracked still counts.
    const tracked = Object.entries(d!.parts).find(([, r]) => r.got.length < r.n)!;
    await recordJoinAnswer(app, ik.userId, [chain[1]], [], { part: { id: tracked[0], i: 2, n: 2 } });
    expect((await readAnswer(app, cid, ik.userId))!.parts[tracked[0]].got.sort()).toEqual([1, 2]);
  });

  it("F4: statements are parsed before they are stored: only join statements for this circle", async () => {
    const jws = (typ: string, payload: object) => `${Buffer.from(JSON.stringify({ alg: "EdDSA", typ, kid: "d_x" })).toString("base64url")}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${Buffer.alloc(64).toString("base64url")}`;
    const mine = jws("p2p-join+jws", { cid, iss: ik.userId, n: 1 });
    const other = jws("p2p-join+jws", { cid: "c_" + "b".repeat(26) });
    const notAJoin = jws("p2p-circle+jws", { cid });
    await recordJoinAnswer(app, ik.userId, [], [mine, other, notAJoin, "junk"], { cid });
    expect((await readAnswer(app, cid, ik.userId))!.joins).toEqual([mine]);
  });

  it("a member who wasn't asked stores nothing", async () => {
    const stranger = generateIdentityKey().userId;
    expect(await recordJoinAnswer(app, stranger, chain, [])).toBe(false);
    expect(await readAnswer(app, cid, stranger)).toBeUndefined();
  });

  it("contiguousTop handles huge inputs without spreading them into Math.max", () => {
    const many = Array.from({ length: 300_000 }, () => "not-a-version");
    expect(contiguousTop([...chain, ...many])).toBe(6);
  });

  it("N1: a link's claimed head can't raise the ceiling (clamped to MAX_CHAIN_IN_BUNDLE, a fixed byte cap)", async () => {
    expect(maxVerFor(1_000_000)).toBe(4096);
    expect(maxVerFor(10)).toBe(266);
    expect(answerByteCap(1_000_000, 1_000_000)).toBe(ANSWER_MAX_BYTES);
    expect(answerByteCap(5, 3)).toBeLessThan(ANSWER_MAX_BYTES);
    // A forged head (parsing doesn't verify signatures) claiming a million versions...
    const forge = (ver: number) => {
      const [h, p] = chain[0].split(".");
      const payload = { ...JSON.parse(Buffer.from(p, "base64url").toString()), ver, prev: Buffer.alloc(32, 7).toString("base64url") };
      return `${h}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${Buffer.alloc(64).toString("base64url")}`;
    };
    const head = forge(1_000_000);
    const a = await u.app();
    await a.load();
    await a.state.update("joins", (cur = {}) => ({ next: { ...cur, [cid]: { cid, head, joins: [], asked: [ik.userId], askedAt: Date.now() } }, result: undefined }));
    const asker = ik.userId;
    await a.state.removeDoc(answerDocName(cid, asker));
    // ...doesn't let versions far above any bootstrappable chain in.
    await recordJoinAnswer(a, asker, [forge(5000), forge(4096)], [], { cid });
    const d = await readAnswer(a, cid, asker);
    expect(d!.versions.map((v) => parseCircleVersion(v).ver)).toEqual([4096]);
    // And a join never starts on such a head.
    await expect(joinCircle(a, { head })).rejects.toThrow(/more than 4096 can be bootstrapped/);
    await a.close();
  });

  it("N-D: a joiner takes as many answers from a confirmer as a member may send it", async () => {
    expect(MAX_NEW_ANSWERS_PER_HOUR).toBe(ANSWERS_PER_ASKER_PER_HOUR);
    expect(MAX_PART_RECORDS).toBeGreaterThan(MAX_NEW_ANSWERS_PER_HOUR);
  });
});

