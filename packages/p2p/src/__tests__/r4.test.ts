// Copyright 2026 Ix Infrastructure Inc.
//
// pre-release review (R4): relays a restore couldn't update are fixed by `p2p
// identity republish` (R4-M2); a watch outlives its certificate on the
// renewed one (R4-L1); a refused relay is retried when the device is still
// listed somewhere (R4-L2).

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { addIdentityVersion, createDeviceCert, createIdentityDoc, generateDeviceKeysV3, peekIdentityDoc } from "@peer2peer/core/v3";
import { main } from "../cli.js";
import { RelayPool } from "../relay-client.js";
import { startRelay, User, type TestRelay } from "./harness.js";

const R1 = "wss://r4-one.test/v3";
const R2 = "wss://r4-two.test/v3";
let r1: TestRelay;
let r2: TestRelay;
let t: Record<string, string>;
const users: User[] = [];

function user(name: string, transport = t, extra = {}): User {
  const u = new User(name, transport, extra);
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

describe("R4-M2: a relay a restore couldn't update", () => {
  it("restore exits 2 (restore_incomplete) with the full result; `p2p identity republish` updates the relay", async () => {
    const owner = user("rp");
    const uid = (await owner.ok(["init", "--name", "rp", "--relay", R1, "--relay", R2, "--yes"])).userId as string;
    const phrase = (await owner.ok(["backup", "show"])).phrase as string;
    // R2 is unreachable during the restore.
    const fresh = user("rp-restored", { [R1]: t[R1], [R2]: "ws://127.0.0.1:9/v3" });
    const r = await fresh.run(["backup", "restore", "--relay", R1, "--relay", R2], { stdin: phrase });
    expect(r.code).toBe(2);
    expect(r.json).toMatchObject({ error: "restore_incomplete", userId: uid, ver: 2 });
    expect(r.json.failed.map((f: { relay: string }) => f.relay)).toEqual([R2]);
    expect(typeof r.json.did).toBe("string");
    expect(peekIdentityDoc(r2.relay.identity.head(uid)!.jws).ver).toBe(1);
    // Later, with R2 reachable: R2 still lists only the old device, so this device gets a
    // restricted connection there, and republish goes over it.
    const later = user("rp-later", t, { P2P_HOME: fresh.home });
    const rp = await later.ok(["identity", "republish"]);
    expect(rp.ok.sort()).toEqual([R1, R2]);
    expect(peekIdentityDoc(r2.relay.identity.head(uid)!.jws).ver).toBe(2);
    expect((await later.ok(["whoami"])).warnings.join(" ")).not.toMatch(/isn't on/);
  });
});

describe("R4-L1: a watch outlives its certificate", () => {
  it("a 4003 close reconnects with the renewed certificate and delivery continues", async () => {
    const a = user("wa", { [R1]: t[R1] });
    await a.ok(["init", "--name", "wa", "--relay", R1, "--yes"]);
    const b = user("wb", { [R1]: t[R1] });
    const bid = (await b.ok(["init", "--name", "wb", "--relay", R1, "--yes"])).userId as string;
    const inv = await a.ok(["invite", "--link"]);
    await b.ok(["accept", inv.link]);
    await a.ok(["friends"]);
    await b.ok(["friends"]);
    await a.ok(["session", "roster", "as", "--add", bid]);
    await a.ok(["status", "--session", "as", "--state", "busy"]);
    // Give a's device a certificate that expires in 4 s, and keep the renewal for later.
    const app = await a.app();
    await app.load();
    const dev = { signingPublicKey: app.device!.signingPublicKey, agreementPublicKey: app.device!.agreementPublicKey };
    const short = createDeviceCert(app.ik!, dev, { ttlSec: 4 });
    const renewed = createDeviceCert(app.ik!, dev);
    await app.state.put("keys", { ...app.keys!, cert: short });
    // The identity document carries only the short certificate too (so nothing longer is adoptable).
    const head = (await app.ownView()).head;
    const doc = createIdentityDoc(app.ik!, { ver: head.ver + 1, prev: head.hash, name: head.name, relays: head.relays, devices: head.devices, keyholders: head.keyholders, by: app.did, certs: [short] });
    await addIdentityVersion(app.store, doc);
    await app.connect({ allowNone: true });
    expect((await app.publishDoc(doc, head.relays)).ok).toEqual([R1]);
    await app.close();
    const lines: string[] = [];
    const ctl = new AbortController();
    const out = { out: [] as string[], err: [] as string[] };
    const watching = main(["watch", "--session", "as", "--jsonl"], {
      env: a.env,
      io: a.io(out),
      signal: ctl.signal,
      writeLine: async (l) => {
        lines.push(l);
        return true;
      },
    });
    await new Promise((r) => setTimeout(r, 1500));
    // Another process renews the certificate (e.g. `maintain`): the keys on disk.
    const app2 = await a.app();
    await app2.load();
    await app2.state.put("keys", { ...app2.keys!, cert: renewed });
    await app2.close();
    // Past the old certificate's expiry and the 1 s reconnect.
    await new Promise((r) => setTimeout(r, 5500));
    expect((await b.ok(["send", "--from-session", "bs", "--to", "wa", "after renewal"])).delivered).toBe(true);
    await new Promise((r) => setTimeout(r, 1500));
    ctl.abort();
    const code = await watching;
    process.exitCode = 0;
    expect(code).toBe(0);
    expect(out.err.join("\n")).toMatch(/certificate expired; reconnecting/);
    expect(lines.map((l) => JSON.parse(l)).some((e) => e.kind === "p2p.message" && e.text === "after renewal")).toBe(true);
  });
});

describe("R4-L2: a refused relay is retried while some branch still lists the device", () => {
  it("retries with backoff on 'retry', and goes fatal on 'fatal'", async () => {
    // An identity whose document on R1 doesn't list `dev`: R1 answers restricted, which this pool refuses.
    const owner = user("fx", { [R1]: t[R1] });
    await owner.ok(["init", "--name", "fx", "--relay", R1, "--yes"]);
    const app = await owner.app();
    await app.load();
    const dev = generateDeviceKeysV3(app.userId);
    const cert = createDeviceCert(app.ik!, dev);
    await app.close();
    for (const verdict of ["retry", "fatal"] as const) {
      const onAuthRefused = vi.fn(async () => verdict);
      const onFatal = vi.fn();
      const pool = new RelayPool({
        relays: [R1],
        transport: () => ({ ws: t[R1], http: "" }),
        auth: { cert, signingSecretKey: dev.signingSecretKey },
        timeoutMs: 2000,
        reconnect: true,
        onAuthRefused,
        onFatal,
      });
      await pool.connect();
      await new Promise((r) => setTimeout(r, 3500));
      pool.close();
      if (verdict === "retry") {
        expect(pool.dials.get(R1)).toBeGreaterThanOrEqual(2);
        expect(onFatal).not.toHaveBeenCalled();
      } else {
        expect(pool.dials.get(R1)).toBe(1);
        expect(onFatal).toHaveBeenCalled();
      }
    }
  });
});
