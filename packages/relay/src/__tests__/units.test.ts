// Copyright 2026 Ix Infrastructure Inc.
// Unit tests: the crypto seam's temporary adapter, config, rate limiter, and
// the Store contract (both implementations).

import { describe, expect, it } from "vitest";
import { sha256 } from "@peer2peer/core";
import { DEFAULT_LIMITS, limitEnvName, loadConfig, RELAY_PRESETS } from "../config.js";
import { b32Encode, createRelayCrypto, RelayCryptoError, testRelayCrypto } from "../crypto.js";
import { createLogger, redact } from "../log.js";
import { RateLimiter } from "../ratelimit.js";
import { SqliteStore } from "../sqlite-store.js";
import { MemoryStore, type Store } from "../store.js";
import { DAY, makeDevice, makeIdentity, signCert } from "./helpers.js";

const c = createRelayCrypto();

describe("canonicalRelayUrl (§5.1)", () => {
  const cases: [string, string][] = [
    ["wss://relay.example.org/v3", "wss://relay.example.org/v3"],
    ["wss://Relay.Example.ORG/v3", "wss://relay.example.org/v3"],
    ["wss://relay.example.org:443/v3", "wss://relay.example.org/v3"],
    ["wss://relay.example.org:8443/v3", "wss://relay.example.org:8443/v3"],
    ["wss://relay.example.org/v3/", "wss://relay.example.org/v3"],
    ["wss://relay.example.org", "wss://relay.example.org/v3"],
    ["wss://relay.example.org/", "wss://relay.example.org/v3"],
    ["wss://relay.example.org/custom/path", "wss://relay.example.org/custom/path"],
    ["wss://bücher.example/v3", "wss://xn--bcher-kva.example/v3"],
  ];
  for (const [input, want] of cases) it(`${input} → ${want}`, () => expect(c.canonicalRelayUrl(input)).toBe(want));

  for (const bad of ["ws://relay.example.org/v3", "https://relay.example.org/v3", "wss://relay.example.org/v3?x=1", "wss://relay.example.org/v3#f", "wss://u:p@relay.example.org/v3", "relay.example.org"]) {
    it(`rejects ${bad}`, () => expect(() => c.canonicalRelayUrl(bad)).toThrow(RelayCryptoError));
  }
});

describe("adapter helpers", () => {
  it("b32 is RFC 4648 lowercase without padding", () => {
    const enc = (s: string) => b32Encode(new TextEncoder().encode(s));
    expect(enc("")).toBe("");
    expect(enc("f")).toBe("my");
    expect(enc("fo")).toBe("mzxq");
    expect(enc("foo")).toBe("mzxw6");
    expect(enc("foob")).toBe("mzxw6yq");
    expect(enc("fooba")).toBe("mzxw6ytb");
    expect(enc("foobar")).toBe("mzxw6ytboi");
    expect(b32Encode(sha256(new Uint8Array(1)))).toHaveLength(52);
  });

  it("powOk counts leading zero bits of H(env || nonce)", () => {
    const env = new TextEncoder().encode("envelope");
    expect(c.powOk(env, new Uint8Array(0), 0)).toBe(true);
    let found = -1;
    for (let i = 0; i < 5000 && found < 0; i++) {
      const n = new Uint8Array([i >> 8, i & 255]);
      const buf = new Uint8Array([...env, ...n]);
      const h = sha256(buf);
      if (h[0] === 0 && h[1] >> 4 === 0) found = i;
    }
    expect(found).toBeGreaterThanOrEqual(0);
    const nonce = new Uint8Array([found >> 8, found & 255]);
    expect(c.powOk(env, nonce, 12)).toBe(true);
    expect(c.powOk(env, nonce, 8)).toBe(true);
    // Find one that fails 12 bits but passes 4.
    const h = (n: Uint8Array) => sha256(new Uint8Array([...env, ...n]));
    for (let i = 0; i < 500; i++) {
      const n = new Uint8Array([i]);
      const d = h(n);
      if (d[0] === 0 && d[1] === 0) continue; // keep the oracle below to two bytes
      const lz = d[0] === 0 ? 8 + Math.clz32(d[1]) - 24 : Math.clz32(d[0]) - 24;
      expect(c.powOk(env, n, lz)).toBe(true);
      expect(c.powOk(env, n, lz + 1)).toBe(false);
    }
  });

  it("verifyDeviceCert rejects a small-order spk", () => {
    const id = makeIdentity();
    const now = Math.floor(Date.now() / 1000);
    const dev = makeDevice(id, now);
    expect(c.verifyDeviceCert(dev.cert, { now }).did).toBe(dev.did);
    // The identity point (a small-order key) as spk.
    const identityPoint = new Uint8Array(32);
    identityPoint[0] = 1;
    const cert = signCert(id, identityPoint, dev.kpk, now);
    expect(() => c.verifyDeviceCert(cert, { now })).toThrow(expect.objectContaining({ code: "weak-key" }));
  });

  it("verifyDeviceCert enforces the 90-day lifetime", () => {
    const id = makeIdentity();
    const now = 2_000_000_000;
    const ok = makeDevice(id, now, { iat: now - 10, exp: now - 10 + 90 * DAY });
    expect(() => c.verifyDeviceCert(ok.cert, { now })).not.toThrow();
    const long = makeDevice(id, now, { iat: now - 10, exp: now - 10 + 90 * DAY + 1 });
    expect(() => c.verifyDeviceCert(long.cert, { now })).toThrow(RelayCryptoError);
  });

  it("the test double replaces only what it overrides", () => {
    const d = testRelayCrypto({ powOk: () => true });
    expect(d.powOk(new Uint8Array(), new Uint8Array(), 24)).toBe(true);
    expect(d.canonicalRelayUrl("wss://A.test")).toBe("wss://a.test/v3");
  });
});

describe("config", () => {
  it("defaults match §5.4 and §5.7", () => {
    const cfg = loadConfig(c, { env: {} });
    expect(cfg.limits).toEqual(DEFAULT_LIMITS);
    expect(cfg.port).toBe(8080);
    expect(cfg.relayUrl).toBe("wss://localhost:8080/v3");
    expect(cfg.powBits).toBe(0);
  });

  it("reads env vars over the JSON file", () => {
    const file = JSON.stringify({ relayUrl: "wss://file.example/v3", port: 9000, limits: { mailboxEnvelopes: 500 }, policy: "file policy" });
    const cfg = loadConfig(c, {
      env: {
        RELAY_CONFIG: "/etc/relay.json",
        RELAY_URL: "wss://Relay.Example.org:443/v3/",
        POW_BITS: "10",
        OPERATOR_CONTACT: "ops@example.org",
        LIMIT_CONTACT_PER_PAIR_PER_HOUR: "5",
        TRUST_PROXY: "2",
        METRICS_PORT: "off",
        LOG_LEVEL: "warn",
      },
      readFile: (p) => {
        expect(p).toBe("/etc/relay.json");
        return file;
      },
    });
    expect(cfg.relayUrl).toBe("wss://relay.example.org/v3");
    expect(cfg.port).toBe(9000);
    expect(cfg.powBits).toBe(10);
    expect(cfg.operatorContact).toBe("ops@example.org");
    expect(cfg.policy).toBe("file policy");
    expect(cfg.limits.mailboxEnvelopes).toBe(500);
    expect(cfg.limits.contactPerPairPerHour).toBe(5);
    expect(cfg.trustProxy).toBe(2);
    expect(cfg.metricsPort).toBeNull();
    expect(loadConfig(c, { env: { TRUST_PROXY: "yes" } }).trustProxy).toBe(1);
    expect(loadConfig(c, { env: {} }).trustProxy).toBe(0);
    expect(loadConfig(c, { env: {} }).metricsPort).toBe(9464);
    expect(loadConfig(c, { env: {} }).metricsHost).toBe("127.0.0.1");
    expect(loadConfig(c, { env: {} }).debugStats).toBe(false);
    expect(loadConfig(c, { env: { DEBUG_STATS: "1" } }).debugStats).toBe(true);
    expect(loadConfig(c, { env: { DEBUG_STATS: "nope" } }).debugStats).toBe(false);
    expect(cfg.logLevel).toBe("warn");
  });

  it("no preset keeps the defaults and the store's own SQLite tuning", () => {
    const cfg = loadConfig(c, { env: {} });
    expect(cfg.preset).toBeUndefined();
    expect(cfg.storage).toEqual({});
    expect(loadConfig(c, { env: { RELAY_PRESET: "default" } }).limits).toEqual(DEFAULT_LIMITS);
    // The defaults themselves are unchanged by the preset's existence.
    expect(DEFAULT_LIMITS.storeMaxBytes).toBe(4 * 1024 ** 3);
    expect(DEFAULT_LIMITS.maxConnections).toBe(10_000);
  });

  it("RELAY_PRESET=small loads the small-device values", () => {
    const MiB = 1024 * 1024;
    const cfg = loadConfig(c, { env: { RELAY_PRESET: "Small" } });
    expect(cfg.preset).toBe("small");
    expect(cfg.limits).toEqual({ ...DEFAULT_LIMITS, ...RELAY_PRESETS.small.limits });
    expect(cfg.limits.storeMaxBytes).toBe(448 * MiB);
    expect(cfg.limits.storeHardMaxBytes).toBe(512 * MiB);
    expect(cfg.limits.maxConnections).toBe(400);
    expect(cfg.limits.mailboxBytes).toBe(16 * MiB);
    expect(cfg.limits.sourceMaxBytes).toBe(256 * MiB);
    // Per-address limits stay moderate, so one address behind a public tunnel can't take the relay.
    expect(cfg.limits.maxConnectionsPerIp).toBe(64);
    expect(cfg.limits.maxConnectionsPerIpv4).toBe(64);
    expect(cfg.limits.maxUnauthPerIp).toBe(8);
    expect(cfg.limits.newDevicesPerIpPerDay).toBe(100);
    expect(cfg.limits.newDevicesPerIpv4PerDay).toBe(100);
    expect(cfg.limits.authsPerIpPerMinute).toBe(60);
    expect(cfg.limits.authsPerIpv4PerMinute).toBe(60);
    for (const k of ["maxConnectionsPerIp", "maxConnectionsPerIpv4", "newDevicesPerIpv4PerDay", "authsPerIpv4PerMinute", "maxUnauthPerIp"] as const) {
      expect(cfg.limits[k]).toBeLessThanOrEqual(DEFAULT_LIMITS[k]);
      expect(cfg.limits[k]).toBeLessThan(cfg.limits.maxConnections);
    }
    // Protocol sizes are not the preset's to change.
    expect(cfg.limits.frameBytes).toBe(DEFAULT_LIMITS.frameBytes);
    expect(cfg.limits.envelopeBytes).toBe(DEFAULT_LIMITS.envelopeBytes);
    expect(cfg.limits.retentionSec).toBe(DEFAULT_LIMITS.retentionSec);
    expect(cfg.storage).toEqual({ walLimitBytes: 64 * MiB, journalSizeLimitBytes: 16 * MiB, checkpointIntervalMs: 500 });
    // Every preset limit is a real limit, and no preset loosens the global caps.
    for (const [k, v] of Object.entries(RELAY_PRESETS.small.limits)) {
      expect(k in DEFAULT_LIMITS).toBe(true);
      expect(v).toBeGreaterThan(0);
    }
    expect(cfg.limits.storeHardMaxBytes).toBeLessThanOrEqual(DEFAULT_LIMITS.storeHardMaxBytes);
    expect(cfg.limits.maxConnections).toBeLessThanOrEqual(DEFAULT_LIMITS.maxConnections);
  });

  it("the JSON file and env vars override the preset, one value at a time", () => {
    const MiB = 1024 * 1024;
    const file = JSON.stringify({ preset: "small", limits: { maxConnections: 300 }, storage: { journalSizeLimitBytes: 8 * MiB } });
    const cfg = loadConfig(c, {
      env: { RELAY_CONFIG: "/etc/relay.json", LIMIT_STORE_MAX_BYTES: String(256 * MiB), SQLITE_CHECKPOINT_INTERVAL_MS: "1000" },
      readFile: () => file,
    });
    expect(cfg.preset).toBe("small");
    expect(cfg.limits.maxConnections).toBe(300);
    expect(cfg.limits.storeMaxBytes).toBe(256 * MiB);
    expect(cfg.limits.storeHardMaxBytes).toBe(512 * MiB);
    expect(cfg.limits.mailboxEnvelopes).toBe(RELAY_PRESETS.small.limits.mailboxEnvelopes);
    expect(cfg.storage).toEqual({ walLimitBytes: 64 * MiB, journalSizeLimitBytes: 8 * MiB, checkpointIntervalMs: 1000 });
    // RELAY_PRESET in the env wins over the file's preset.
    const plain = loadConfig(c, { env: { RELAY_CONFIG: "/etc/relay.json", RELAY_PRESET: "default" }, readFile: () => file });
    expect(plain.preset).toBeUndefined();
    expect(plain.limits.storeMaxBytes).toBe(DEFAULT_LIMITS.storeMaxBytes);
    expect(plain.limits.maxConnections).toBe(300);
    // An override past the preset's hard cap must raise the hard cap too.
    expect(() => loadConfig(c, { env: { RELAY_PRESET: "small", LIMIT_STORE_MAX_BYTES: String(1024 * MiB) } })).toThrow(/storeHardMaxBytes/);
    // SQLite tuning works without a preset.
    expect(loadConfig(c, { env: { SQLITE_WAL_LIMIT_BYTES: String(32 * MiB) } }).storage).toEqual({ walLimitBytes: 32 * MiB });
  });

  it("the store applies the preset's journal_size_limit", () => {
    const pragma = (st: SqliteStore) =>
      Object.values((st as unknown as { db: { prepare(q: string): { get(): Record<string, number> } } }).db.prepare("PRAGMA journal_size_limit").get())[0];
    const plain = new SqliteStore(":memory:");
    const small = new SqliteStore(":memory:", { ...loadConfig(c, { env: { RELAY_PRESET: "small" } }).storage });
    try {
      expect(pragma(plain)).toBe(64 * 1024 * 1024);
      expect(pragma(small)).toBe(16 * 1024 * 1024);
    } finally {
      plain.close();
      small.close();
    }
  });

  it("rejects an unknown preset and bad SQLite tuning", () => {
    expect(() => loadConfig(c, { env: { RELAY_PRESET: "tiny" } })).toThrow(/RELAY_PRESET/);
    expect(() => loadConfig(c, { env: { RELAY_PRESET: "__proto__" } })).toThrow(/RELAY_PRESET/);
    expect(() => loadConfig(c, { env: { SQLITE_CHECKPOINT_INTERVAL_MS: "0" } })).toThrow(/SQLITE_CHECKPOINT_INTERVAL_MS/);
    // The checkpoint interval is capped at 10 s, from the env and from the file alike.
    expect(loadConfig(c, { env: { SQLITE_CHECKPOINT_INTERVAL_MS: "10000" } }).storage?.checkpointIntervalMs).toBe(10_000);
    expect(() => loadConfig(c, { env: { SQLITE_CHECKPOINT_INTERVAL_MS: "10001" } })).toThrow(/SQLITE_CHECKPOINT_INTERVAL_MS/);
    expect(() =>
      loadConfig(c, { env: { RELAY_CONFIG: "/etc/relay.json" }, readFile: () => JSON.stringify({ storage: { checkpointIntervalMs: 60_000 } }) }),
    ).toThrow(/SQLITE_CHECKPOINT_INTERVAL_MS/);
    expect(() => loadConfig(c, { env: { SQLITE_WAL_LIMIT_BYTES: "1.5" } })).toThrow(/SQLITE_WAL_LIMIT_BYTES/);
  });

  it("rejects bad values", () => {
    expect(() => loadConfig(c, { env: { POW_BITS: "25" } })).toThrow(/POW_BITS/);
    expect(() => loadConfig(c, { env: { PORT: "http" } })).toThrow(/PORT/);
    expect(() => loadConfig(c, { env: { RELAY_URL: "http://x/v3" } })).toThrow();
    expect(() => loadConfig(c, { env: { LOG_LEVEL: "loud" } })).toThrow(/LOG_LEVEL/);
    expect(() => loadConfig(c, { env: { LIMIT_FRAME_BYTES: "1000" } })).toThrow(/frameBytes/);
  });

  it("names limit env vars in upper snake case", () => {
    expect(limitEnvName("mailboxEnvelopes")).toBe("LIMIT_MAILBOX_ENVELOPES");
    expect(limitEnvName("sendsPerMinute")).toBe("LIMIT_SENDS_PER_MINUTE");
  });
});

describe("logging", () => {
  it("emits JSON lines at or above the level, and redacts ids to a salted hash", () => {
    const lines: string[] = [];
    const log = createLogger({ level: "info", sink: (l) => lines.push(l), now: () => 0 });
    log.debug("hidden");
    log.info("shown", { n: 1 });
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0])).toEqual({ ts: "1970-01-01T00:00:00.000Z", level: "info", msg: "shown", n: 1 });
    expect(log.debugEnabled).toBe(false);
    const id = makeIdentity().userId;
    expect(redact(id)).toMatch(/^h:[A-Za-z0-9_-]{12}$/);
    expect(redact(id)).toBe(redact(id));
    expect(redact(id)).not.toContain(id.slice(4, 16));
  });
});

describe("RateLimiter", () => {
  it("bursts to the limit, then refills continuously", () => {
    let t = 0;
    const rl = new RateLimiter(3, 60_000, () => t);
    expect([rl.take("a"), rl.take("a"), rl.take("a"), rl.take("a")]).toEqual([true, true, true, false]);
    expect(rl.take("b")).toBe(true);
    t += 20_000;
    expect(rl.has("a")).toBe(true);
    expect(rl.take("a")).toBe(true);
    expect(rl.take("a")).toBe(false);
    t += 10 * 60_000;
    rl.prune();
    expect(rl.size).toBe(0);
  });

  it("a zero limit allows nothing", () => {
    const rl = new RateLimiter(0, 60_000, () => 0);
    expect(rl.take("a")).toBe(false);
  });
});

for (const [name, mk] of [
  ["MemoryStore", () => new MemoryStore()],
  ["SqliteStore", () => new SqliteStore(":memory:")],
] as [string, () => Store][]) {
  describe(`Store contract: ${name}`, () => {
    const caps = { maxEnvelopes: 100, maxBytes: 1 << 20 };
    const noSweep = { envelopesBefore: 0, capsBefore: 0, identityVersionsBefore: 0, devicesBefore: 0 };

    it("binds a did to its first iss only, refreshes last-seen, and prunes unseen bindings", () => {
      const s = mk();
      s.touchDevice("d_x", "p2p:a", 1);
      s.touchDevice("d_x", "p2p:b", 2);
      s.touchDevice("d_y", "p2p:a", 1);
      expect(s.deviceIssuer("d_x")).toBe("p2p:a");
      expect(s.deviceIssuer("d_z")).toBeUndefined();
      s.touchDevice("d_x", "p2p:a", 100); // seen again
      s.touchDevice("d_y", "p2p:b", 100); // a different iss doesn't refresh
      expect(s.sweep({ ...noSweep, devicesBefore: 50 }, 1e9).devices).toBe(1);
      expect(s.deviceIssuer("d_x")).toBe("p2p:a");
      expect(s.deviceIssuer("d_y")).toBeUndefined();
      s.close();
    });

    it("stores, pages, acks and caps envelopes", () => {
      const s = mk();
      const rids = [1, 2, 3, 4].map((i) => s.putEnvelope({ to: "u", tdid: "d", env: `e${i}`, size: 10, receivedAt: i, src: "s" }, caps).rid);
      s.putEnvelope({ to: "u", tdid: "other", env: "o", size: 10, receivedAt: 1, src: "s" }, caps);
      expect(s.envelopesAfter("u", "d", 0, 0, 2).map((e) => e.env)).toEqual(["e1", "e2"]);
      expect(s.envelopesAfter("u", "d", rids[1], 0, 10).map((e) => e.env)).toEqual(["e3", "e4"]);
      expect(s.envelopesAfter("u", "d", 0, 3, 10).map((e) => e.env)).toEqual(["e3", "e4"]);
      expect(s.ackEnvelopes("u", "other", [rids[0]])).toEqual({ count: 0, bytes: 0 });
      expect(s.ackEnvelopes("u", "d", [rids[0], rids[2], 999])).toEqual({ count: 2, bytes: 20 });
      expect(s.counts()).toMatchObject({ envelopes: 3, envelopeBytes: 30 });
      const r = s.putEnvelope({ to: "u", tdid: "d", env: "e5", size: 10, receivedAt: 5, src: "s" }, { maxEnvelopes: 2, maxBytes: 1 << 20 });
      expect(r).toMatchObject({ dropped: 1, droppedBytes: 10 });
      expect(s.envelopesAfter("u", "d", 0, 0, 10).map((e) => e.env)).toEqual(["e4", "e5"]);
      const b = s.putEnvelope({ to: "u", tdid: "d", env: "e6", size: 15, receivedAt: 6, src: "s" }, { maxEnvelopes: 100, maxBytes: 25 });
      expect(b.dropped).toBe(1);
      expect(s.envelopesAfter("u", "d", 0, 0, 10).map((e) => e.env)).toEqual(["e5", "e6"]);
      // rids are never reused, even after deletes.
      const next = s.putEnvelope({ to: "u", tdid: "d", env: "e7", size: 1, receivedAt: 7, src: "s" }, caps).rid;
      expect(next).toBeGreaterThan(b.rid);
      s.close();
    });

    it("tracks cap state and sweeps it", () => {
      const s = mk();
      expect(s.capState("k")).toEqual({ revoked: false, uses: 0 });
      s.useCap("k", 10);
      s.useCap("k", 11);
      s.revokeCap("j", 12);
      expect(s.capState("k")).toEqual({ revoked: false, uses: 2 });
      expect(s.capState("j")).toEqual({ revoked: true, uses: 0 });
      expect(s.sweep({ ...noSweep, capsBefore: 12 }, 1e9).caps).toBe(1);
      expect(s.capState("k")).toEqual({ revoked: false, uses: 0 });
      expect(s.capState("j").revoked).toBe(true);
      s.close();
    });

    it("stores identity docs and sweeps only non-tips", () => {
      const s = mk();
      const doc = (hash: string, ver: number, prev: string | null, merge: string | null = null) => ({
        hash,
        iss: "p2p:a",
        ver,
        prev,
        merge,
        jws: `jws-${hash}`,
        devices: ["d_1"],
        iat: 1,
        exp: 2,
        receivedAt: 1,
      });
      expect(s.putIdentityDoc(doc("h1", 1, null))).toBe(true);
      expect(s.putIdentityDoc(doc("h1", 1, null))).toBe(false);
      s.putIdentityDoc(doc("h2a", 2, "h1"));
      s.putIdentityDoc(doc("h2b", 2, "h1"));
      s.putIdentityDoc(doc("h3", 3, "h2b", "h2a"));
      expect(s.identityDocs("p2p:a").map((d) => d.hash).sort()).toEqual(["h1", "h2a", "h2b", "h3"]);
      expect(s.identityDoc("h3")).toMatchObject({ merge: "h2a", devices: ["d_1"], iat: 1, exp: 2 });
      expect(s.sweep({ ...noSweep, identityVersionsBefore: 2 }, 1e9).identityDocs).toBe(3);
      expect(s.identityDocs("p2p:a").map((d) => d.hash)).toEqual(["h3"]);
      s.deleteIdentityDocs(["h3"]);
      expect(s.identityDocs("p2p:a")).toEqual([]);
      expect(s.ping()).toBe(true);
      s.close();
    });

    it("keeps a per-userId index, lists expired heads, and deletes a whole identity", () => {
      const s = mk();
      const idx = { iss: "p2p:a", head: "h2", headVer: 2, headExp: 100, tips: ["h2"], allowed: ["d_1"], cap: null, leftAt: null };
      s.putIdentityIndex(idx);
      s.putIdentityIndex({ ...idx, iss: "p2p:b", headExp: 300 });
      s.putIdentityDoc({ hash: "h2", iss: "p2p:a", ver: 2, prev: null, merge: null, jws: "j", devices: [], iat: 1, exp: 100, receivedAt: 1 });
      expect(s.identityIndex("p2p:a")).toEqual(idx);
      expect(s.expiredIdentities(200, 10)).toEqual(["p2p:a"]);
      s.deleteIdentity("p2p:a");
      expect(s.identityIndex("p2p:a")).toBeUndefined();
      expect(s.identityDocs("p2p:a")).toEqual([]);
      expect(s.identityIndex("p2p:b")).toBeDefined();
      s.close();
    });
  });
}
