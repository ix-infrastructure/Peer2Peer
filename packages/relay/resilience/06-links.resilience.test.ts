// Copyright 2026 Ix Infrastructure Inc.
// #6 Link-mailbox reservation limits: per device, per IP, the global byte
// reservation, entry size and count, and the unauthenticated op rate.

import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { b32Encode } from "../src/crypto.js";
import type { TestClient } from "../src/__tests__/helpers.js";
import { assertHealthy, authedFrom, Canary, connectFrom, newDevice, Sampler, tally } from "./harness/load.js";
import { RelayProcess } from "./harness/relay-process.js";

const ENTRY = 16 * 1024;
const limits = {
  linkOpenPerDevice: 2,
  linkOpenPerIp: 3,
  linkReqEntries: 4,
  linkEntryBytes: ENTRY,
  // Room for exactly five mailboxes ((4 req + 1 resp) x 16 KiB each).
  linkTotalBytes: 5 * 5 * ENTRY,
  linkOpsPerIpPerMinute: 40,
  linkOpenPerIssPerHour: 20,
  linkOpenPerIpPerHour: 30,
  linkTtlSec: 600,
};

let relay: RelayProcess;
let canary: Canary | undefined;
afterEach(async () => {
  canary?.close();
  await relay?.dispose();
});

const lid = (): string => b32Encode(new Uint8Array(randomBytes(17))).slice(0, 26);
const code = (r: Record<string, unknown>): string => (r.t === "error" ? String(r.code) : String(r.t));
const openLink = async (c: TestClient, l = lid()) => code(await c.request({ t: "link-open", lid: l }));

describe("6. link-mailbox reservation limits", () => {
  it("caps open mailboxes per device, per IP and by the global byte reservation; expiry frees room for the canary", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);

    // One device: 2 per device.
    const d1 = await authedFrom(relay, newDevice(relay), "198.51.100.60");
    const first = lid();
    const perDevice = [await openLink(d1, first), await openLink(d1), await openLink(d1)];
    // A second device on the same IP: 3 per IP.
    const d2 = await authedFrom(relay, newDevice(relay), "198.51.100.60");
    const perIp = [await openLink(d2), await openLink(d2)];
    // Two more IPs fill the global reservation (5 mailboxes); a sixth IP is refused.
    const d3 = await authedFrom(relay, newDevice(relay), "198.51.100.61");
    const d4 = await authedFrom(relay, newDevice(relay), "198.51.100.62");
    const d5 = await authedFrom(relay, newDevice(relay), "198.51.100.63");
    const global = [await openLink(d3), await openLink(d4), await openLink(d5)];
    const reopen = await openLink(d3, first);
    const full = await relay.stats();

    // The canary can't open one while the budget is full (by design: opens are
    // refused, never puts into mailboxes already open) ...
    const canaryWhileFull = await openLink(canary.bc);
    // ... and can once the attacker's mailboxes expire.
    await relay.advance((limits.linkTtlSec + 1) * 1000);
    const canaryAfterTtl = await openLink(canary.bc);
    const after = await relay.stats();

    await assertHealthy({
      test: "6a link reservations",
      relay,
      sampler,
      canary,
      limits,
      extra: { perDevice, perIp, global, reopen, reservedFull: full.links.reservedBytes, canaryWhileFull, canaryAfterTtl, openAfterTtl: after.links.open },
    });
    expect(perDevice).toEqual(["ok", "ok", "full"]);
    expect(perIp).toEqual(["ok", "full"]);
    expect(global).toEqual(["ok", "ok", "full"]);
    expect(reopen).toBe("exists");
    expect(full.links.open).toBe(5);
    expect(full.links.reservedBytes).toBeLessThanOrEqual(limits.linkTotalBytes);
    expect(canaryWhileFull).toBe("full");
    expect(canaryAfterTtl).toBe("ok");
    expect(after.links.open).toBe(1);
  });

  it("bounds entries per mailbox and bytes per entry, and rate-limits unauthenticated link ops per IP", async () => {
    relay = await RelayProcess.start({ limits, env: { TRUST_PROXY: "1" } });
    const sampler = await Sampler.start(relay);
    canary = await Canary.start(relay);
    const owner = await authedFrom(relay, newDevice(relay), "198.51.100.64");
    const l = lid();
    expect(await openLink(owner, l)).toBe("ok");

    // Anyone may put into `req`: 4 entries of at most 16 KiB.
    const putter = await connectFrom(relay, "198.51.100.65");
    const puts: string[] = [];
    for (let i = 0; i < 5; i++) puts.push(code(await putter.request({ t: "link-put", lid: l, slot: "req", data: "x".repeat(ENTRY) })));
    const oversize = code(await putter.request({ t: "link-put", lid: l, slot: "req", data: "x".repeat(ENTRY + 1) }));
    const respByStranger = code(await putter.request({ t: "link-put", lid: l, slot: "resp", data: "hi" }));
    const got = await putter.request({ t: "link-get", lid: l, slot: "req" });

    // 40 link ops per IP per minute: a scanner from one IP is cut off.
    const scanner = await connectFrom(relay, "198.51.100.66");
    const scans: string[] = [];
    for (let i = 0; i < 50; i++) scans.push(code(await scanner.request({ t: "link-get", lid: lid(), slot: "req" })));
    // A getter on another IP is unaffected.
    const other = await connectFrom(relay, "198.51.100.67");
    const otherGet = code(await other.request({ t: "link-get", lid: l, slot: "req" }));
    const st = await relay.stats();

    await assertHealthy({
      test: "6b link entries + op rate",
      relay,
      sampler,
      canary,
      limits,
      extra: { puts, oversize, respByStranger, entries: (got.entries as string[]).length, scans: tally(scans), otherGet, reserved: st.links.reservedBytes },
    });
    expect(puts).toEqual(["ok", "ok", "ok", "ok", "full"]);
    expect(oversize).toBe("too-large");
    expect(respByStranger).toBe("forbidden");
    expect(got.entries).toHaveLength(4);
    expect(tally(scans)).toEqual({ "not-found": 40, "rate-limited": 10 });
    expect(otherGet).toBe("link");
    // Puts never grow the reservation made at open.
    expect(st.links.reservedBytes).toBe(5 * ENTRY);
  });
});
