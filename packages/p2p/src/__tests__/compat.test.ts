// Copyright 2026 Ix Infrastructure Inc.
//
// Forward compatibility in the CLI (docs/compatibility.md): unknown plaintext fields are ignored,
// an envelope of an unknown kind is verified, admitted to the replay window and surfaced once,
// peerSupports gates new features on evidence only, device info rides in the identity document
// only when opted in and every relay stores it, and doctor and ls show versions and caps.

import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { App } from "../app.js";
import { CLI_CAPS, PROTO_CAP, protoMinor, supportsIn, unavailableBetween } from "../features.js";
import { relaysSupport } from "../relay-info.js";
import { onUnknownKind } from "../unknown-kinds.js";
import { sessKey, type PeerStatusRec } from "../state.js";
import { VERSION } from "../version.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R = "wss://relay-compat.test/v3";
let relay: TestRelay;
let ann: User;
let ben: User;
let cat: User;
const ids: Record<string, string> = {};

type Ev = { id: string; kind: string; toSession?: string; data: Record<string, unknown> };
const events = async (u: User): Promise<Ev[]> => ((await (await u.app()).state.get("events"))?.items ?? []) as Ev[];

/** Sends from `from` to `to` an envelope of `kind` with `plaintext`, as a client that knows more would. */
async function rawSend(from: User, to: string, kind: string, session: { own: string; sid: string }, plaintext: object) {
  const app = await from.app();
  await app.load();
  await app.connectAndDrain();
  const d = await app.deliver(to, kind as never, session, plaintext);
  await app.close?.();
  return d;
}

describe("forward compatibility", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    ann = new User("ann", t);
    ben = new User("ben", t);
    cat = new User("cat", t, { P2P_DEVICE_INFO: "1" });
    for (const u of [ann, ben, cat]) ids[u.name] = (await u.ok(["init", "--name", u.name, "--relay", R, "--yes"])).userId;
    for (const u of [ben, cat]) {
      const code = (await ann.ok(["invite"])).code as string;
      await u.ok(["join", "--confirmed", code]);
      await ann.ok(["friends"]);
    }
    await ann.ok(["session", "roster", "a1", "--add", ids.ben]);
    await ann.ok(["status", "--session", "a1", "--state", "idle", "--label", "a1", "--cap", "receipts.v1"]);
    await ben.ok(["session", "roster", "b1", "--add", ids.ann]);
    await ben.ok(["ls"]);
  }, 90_000);

  afterAll(async () => {
    await relay?.close();
    for (const u of [ann, ben, cat]) u?.cleanup();
  });

  it("a msg with a field this version doesn't know arrives, the field dropped; one listed in crit is refused", async () => {
    await rawSend(ben, ids.ann, "msg", { own: ids.ann, sid: "a1" }, { text: "from a newer client", later: { anything: true } });
    await rawSend(ben, ids.ann, "msg", { own: ids.ann, sid: "a1" }, { text: "critical", later: 1, crit: ["later"] });
    const r = await ann.run(["ls"]);
    const got = (await events(ann)).filter((e) => e.kind === "p2p.message");
    expect(got.map((e) => e.data.text)).toEqual(["from a newer client"]);
    expect(JSON.stringify(got[0])).not.toContain("anything");
    expect(r.err).toMatch(/unsupported-critical/);
  }, 60_000);

  it("an envelope of an unknown kind is verified, admitted to the replay window, and surfaced once as data", async () => {
    const d = await rawSend(ben, ids.ann, "futurekind", { own: ids.ann, sid: "a1" }, { whatever: 1 });
    expect(d.relays.length).toBe(1);
    await rawSend(ben, ids.ann, "futurekind", { own: ids.ann, sid: "a1" }, { whatever: 2 });
    const r = await ann.run(["ls"]);
    expect(r.err).toMatch(/sent a "futurekind" envelope this version doesn't understand/);
    expect(r.err).not.toMatch(/rejected an envelope/);
    const notes = (await events(ann)).filter((e) => e.kind === "p2p.unknown");
    // Once per sender and kind a day, to the session it was for; nothing of its content.
    expect(notes).toHaveLength(1);
    expect(notes[0]).toMatchObject({ toSession: "a1", data: { envKind: "futurekind", from: { userId: ids.ben } } });
    expect(JSON.stringify(notes[0])).not.toContain("whatever");
    // Both envelopes were committed: the relay redelivers neither (no "replayed" drops, no new notes).
    const again = await ann.run(["ls"]);
    expect(again.err).not.toMatch(/futurekind|rejected/);
  }, 60_000);

  it("at most 3 notices per sender a day, whatever kinds they make up", async () => {
    for (const k of ["kinda", "kindb", "kindc", "kindd"]) await rawSend(ben, ids.ann, k, { own: ids.ann, sid: "a1" }, {});
    await ann.run(["ls"]);
    const kinds = (await events(ann)).filter((e) => e.kind === "p2p.unknown").map((e) => e.data.envKind);
    // futurekind (earlier) and two more: three for Ben today.
    expect(kinds).toEqual(["futurekind", "kinda", "kindb"]);
  }, 60_000);

  it("an unknown kind from someone the user doesn't know: no notice, no log line, and their device cert isn't kept", async () => {
    const err: string[] = [];
    const app = new App({ env: ann.env, io: { out: () => undefined, err: (s) => err.push(s) } });
    await app.load();
    const stranger = `p2p:${"q".repeat(52)}`;
    const r = {
      ok: true,
      rule: "unknown-kind",
      envelope: { from: stranger, fdid: "d_stranger", own: stranger, sid: "s", ts: Date.now(), kind: "futurekind" },
      plaintext: { kind: "unknown", envKind: "futurekind" },
      sender: { iss: stranger, did: "d_stranger", exp: Math.floor(Date.now() / 1000) + 3600, jws: "a.b.c" },
    } as unknown as Parameters<typeof onUnknownKind>[2];
    expect(await onUnknownKind(app, "env-stranger", r)).toEqual([]);
    expect(err).toEqual([]);
    expect(await app.store.getDeviceCert("d_stranger")).toBeUndefined();
  });

  it("an unknown kind from someone the user unfriended (the friendship ended) is not surfaced", async () => {
    await ann.ok(["unfriend", ids.cat]).catch(() => undefined);
    const before = (await events(ann)).filter((e) => e.kind === "p2p.unknown").length;
    await rawSend(cat, ids.ann, "otherkind", { own: ids.cat, sid: "c1" }, {}).catch(() => undefined);
    await ann.run(["ls"]);
    expect((await events(ann)).filter((e) => e.kind === "p2p.unknown")).toHaveLength(before);
  }, 60_000);

  it("peerSupports: a session by its live status, a device by its identity entry or latest status, a user by all live sessions", () => {
    const now = Date.now();
    const rec = (sid: string, did: string, caps: string[] | undefined, ago = 0): PeerStatusRec => ({ own: "p2p:u", sid, did, ts: now - ago, status: { state: "idle", label: sid, ...(caps ? { caps } : {}) } });
    const peers = { [sessKey("p2p:u", "s1")]: rec("s1", "d_A", ["receipts.v1", PROTO_CAP]), [sessKey("p2p:u", "s2")]: rec("s2", "d_B", undefined, 10 * 60_000) };
    const src = { peers, self: { userId: "p2p:me", did: "d_ME" }, now };
    expect(supportsIn(src, "p2p:u", { sid: "s1" }, "receipts.v1")).toBe(true);
    expect(supportsIn(src, "p2p:u", { sid: "s2" }, "receipts.v1")).toBe(false);
    expect(supportsIn(src, "p2p:u", { did: "d_A" }, PROTO_CAP)).toBe(true);
    expect(supportsIn(src, "p2p:u", { did: "d_B" }, PROTO_CAP)).toBe(false);
    expect(supportsIn({ ...src, dinfo: { d_B: { caps: [PROTO_CAP] } } }, "p2p:u", { did: "d_B" }, PROTO_CAP)).toBe(true);
    expect(supportsIn(src, "p2p:u", { all: true }, "receipts.v1")).toBe(true);
    expect(supportsIn(src, "p2p:nobody", { all: true }, "receipts.v1")).toBe(false);
    expect(protoMinor(["proto.3.1", "proto.3.4"])).toBe(4);
    expect(protoMinor(undefined)).toBe(0);
    // Statuses carry the protocol minor, never the exact client version (it would help single out a device).
    expect(CLI_CAPS.some((c) => c.startsWith("p2p-cli"))).toBe(false);
    expect(unavailableBetween(CLI_CAPS, [["status.tolerant.v1"]]).theyLack).toContain(PROTO_CAP);
  });

  it("ls --json rows carry the device and its protocol minor (not its exact version)", async () => {
    const rows = (await ben.ok(["ls"])).peers as { sid: string; did: string; client?: string; proto?: number }[];
    const a1 = rows.find((r) => r.sid === "a1")!;
    expect(a1.did).toMatch(/^d_/);
    expect(a1.client).toBeUndefined();
    expect(a1.proto).toBe(1);
  }, 60_000);

  it("device info rides in the identity document only when opted in and every relay stores it", async () => {
    // Cat opted in (P2P_DEVICE_INFO=1) and the relay lists identity.lenient: its next document carries dinfo.
    // Any command that connects brings the entry current (a key holder publishes the next version).
    await cat.ok(["ls"]);
    const catApp = await cat.app();
    await catApp.load();
    const own = await catApp.view(ids.cat);
    expect(own?.head.dinfo?.[catApp.did]).toEqual({ caps: [...CLI_CAPS], client: VERSION });
    // A friend's doctor shows the exact version only from there.
    const seen = await ann.ok(["doctor", ids.cat]);
    expect(seen.devices).toEqual([expect.objectContaining({ client: VERSION, source: "identity", proto: 1 })]);
    // Ann didn't opt in: none.
    await ann.ok(["ls"]);
    const annApp = await ann.app();
    await annApp.load();
    expect((await annApp.view(ids.ann))?.head.dinfo).toBeUndefined();
    // A relay that doesn't list identity.lenient (an older relay): none either.
    await catApp.state.update("relayInfo", (cur = {}) => ({ next: { ...cur, [R]: { at: Date.now(), ok: true, minor: 0, features: [], frames: [] } }, result: undefined }));
    expect(await relaysSupport(catApp, [R], "identity.lenient")).toBe(false);
    // Opted out now: the entry is taken out at the next publish (allowed again after an hour; forced here).
    await catApp.updateSelf((s) => ({ ...s, deviceInfoAt: 0 }));
    const off = new User("cat", { [R]: `ws://127.0.0.1:${relay.port}/v3` }, { P2P_DEVICE_INFO: "0" });
    Object.defineProperty(off, "home", { value: cat.home });
    await off.ok(["ls"]);
    const after = new App({ env: cat.env, io: cat.io({ out: [], err: [] }) });
    await after.load();
    expect((await after.view(ids.cat))?.head.dinfo).toBeUndefined();
  }, 90_000);

  it("doctor <user> lists each of their devices with its version and caps, and the features unavailable between you", async () => {
    const r = await ben.ok(["doctor", ids.ann]);
    const versions = (r.checks as { id: string; detail: string }[]).filter((c) => c.id.startsWith("version:"));
    expect(versions).toHaveLength(1);
    // Ann didn't opt in to dinfo: the protocol minor, no exact version.
    expect(versions[0].detail).toMatch(/^protocol 3\.1; understands /);
    expect(versions[0].detail).not.toContain(VERSION);
    expect(r.devices).toEqual([expect.objectContaining({ proto: 1, source: "status" })]);
    expect(r.devices[0].client).toBeUndefined();
    // receipts.v1 is a front end's (Ann's mod advertises it), not compared between CLIs.
    expect(r.unavailable).toEqual({ theyLack: [], weLack: [] });
  }, 60_000);
});
