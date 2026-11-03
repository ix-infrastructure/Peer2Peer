// Copyright 2026 Ix Infrastructure Inc.
//
// Pure pieces: output formatting, config, target parsing, status building,
// circle links, chunking, the watch filter, avatars.

import { describe, expect, it } from "vitest";
import { createCircle, generateIdentityKey } from "@peer2peer/core/v3";
import { encodeCircleLink, parseCircleLink } from "../circle-ops.js";
import { defaultRelays, normalizeRelays, transportResolver, tunables } from "../config.js";
import { CliError, toErrorJson } from "../errors.js";
import { formatAge, formatDelivery, formatJoin, formatPeers, formatRoster, formatWhoami, plural, qr, terminalText } from "../format.js";
import { avatarValue } from "../identity.js";
import { buildStatus, checkSid, parseTarget, sessionRef } from "../sessions.js";
import { chunkBody, splitCircle } from "../sync.js";
import { eventFor, eventLine } from "../watch.js";

describe("format", () => {
  it("ages, plurals and deliveries", () => {
    expect([formatAge(5), formatAge(90), formatAge(7200), formatAge(3 * 86400)]).toEqual(["5s", "1m", "2h", "3d"]);
    expect(plural(1, "relay")).toBe("1 relay");
    expect(plural(2, "relay")).toBe("2 relays");
    expect(formatDelivery({ relays: ["a", "b"], devices: 1 })).toBe("delivered via 2 relays (1 device)");
    expect(formatDelivery({ relays: [], devices: 2 })).toBe("delivered via 0 relays (2 devices)");
  });

  it("peers: live marker, summary, files, stale", () => {
    const base = { own: "p2p:x", sid: "s", ref: "abcdef", address: "bob@aaaa-bbbb-cccc-dddd", self: false, thisDevice: false, label: "api", files: [] as string[] };
    const out = formatPeers([
      { ...base, live: true, ageSec: 12, state: "busy", repo: "web", branch: "main", summary: "fixing auth", files: ["a.ts", "b.ts"] },
      { ...base, sid: "t", ref: "123456", live: false, ageSec: 4000, state: "idle" },
    ]);
    expect(out).toContain("● bob@aaaa-bbbb-cccc-dddd [abcdef] api busy  web@main  12s ago");
    expect(out).toContain("    fixing auth");
    expect(out).toContain("    files: a.ts, b.ts");
    expect(out).toContain("· bob@aaaa-bbbb-cccc-dddd [123456] api idle  1h ago (stale)");
    expect(formatPeers([])).toMatch(/No live sessions/);
  });

  it("whoami, roster and join texts", () => {
    const w = formatWhoami({
      userId: "p2p:abc",
      name: "carol",
      address: "carol@k7f2-qx9a-3m4n-5p6q",
      fingerprint: "k7f2-qx9a-3m4n-5p6q",
      did: "d_x",
      keyholder: true,
      devices: [{ did: "d_x", label: "laptop", keyholder: true, thisDevice: true, certExp: 1800000000 }],
      relays: ["wss://r.example/v3"],
      doc: { ver: 2, exp: 1800000000, freshness: "fresh", daysPastExp: 0, forked: false, historyGap: false },
      profile: { links: [] },
      proofs: 0,
      warnings: ["back up"],
    });
    expect(w).toMatch(/^carol@k7f2-qx9a-3m4n-5p6q\n/);
    expect(w).toContain("d_x *");
    expect(w).toContain("key holder");
    expect(w).toContain("! back up");
    expect(formatRoster({ sid: "s", ref: "abcdef", ver: 1, vis: "private", parts: [] })).toContain("nobody else (private)");
    expect(formatRoster({ sid: "s", ref: "abcdef", ver: 2, vis: "circle", circle: "c_x", circleName: "team", parts: [], openCircle: true })).toMatch(/circle team[\s\S]*open/);
    const j = { cid: "c", name: "team", owner: "o", ownerAddress: "o@x", founder: "f", ownershipChanged: true, policy: "open" as const, asked: [], answered: [] };
    expect(formatJoin({ ...j, status: "joined", confirmation: "owner-only" })).toMatch(/Joined "team".*founded by f.*no other member/);
    expect(formatJoin({ ...j, status: "waiting" })).toMatch(/no answer yet/);
    expect(formatJoin({ ...j, status: "unconfirmed" })).toMatch(/--yes/);
  });

  it("qr renders, terminal text is sanitized", () => {
    expect(qr("p2p-link:abcdefghijklmnopqrstuvwxyz@relay.example/v3").split("\n").length).toBeGreaterThan(10);
    expect(terminalText("hi\u001b[31m <script>\u202e")).toBe("hi[31m script");
  });

  it("errors map to {error, reason}", () => {
    expect(toErrorJson(new CliError("x", "why", { extra: 1 }))).toEqual({ error: "x", reason: "why", extra: 1 });
    expect(toErrorJson(new Error("boom"))).toEqual({ error: "internal", reason: "boom" });
  });
});

describe("config", () => {
  it("canonicalises relays, bounds them to 5, and reads defaults from env then file", () => {
    expect(normalizeRelays(["wss://R.Example/", "wss://r.example/v3", "wss://x.example:443/p/"])).toEqual(["wss://r.example/v3", "wss://x.example/p"]);
    expect(() => normalizeRelays(["https://r.example"])).toThrow(CliError);
    expect(() => normalizeRelays(["a", "b", "c", "d", "e", "f"].map((h) => `wss://${h}.example`))).toThrow(/at most 5/);
    expect(defaultRelays({ P2P_DEFAULT_RELAYS: "wss://a.example, wss://b.example" }, { defaultRelays: ["wss://c.example"] })).toEqual(["wss://a.example/v3", "wss://b.example/v3"]);
    expect(defaultRelays({}, { defaultRelays: ["wss://c.example"] })).toEqual(["wss://c.example/v3"]);
    expect(defaultRelays({}, {})).toEqual([]);
  });

  it("maps canonical relays to dial URLs, else dials them directly", () => {
    const t = transportResolver({ P2P_RELAY_TRANSPORT: JSON.stringify({ "wss://relay.test/v3": "ws://127.0.0.1:9/v3/" }) }, {});
    expect(t("wss://RELAY.test")).toEqual({ ws: "ws://127.0.0.1:9/v3", http: "http://127.0.0.1:9/v3" });
    expect(t("wss://other.example:8443/x")).toEqual({ ws: "wss://other.example:8443/x", http: "https://other.example:8443/x" });
    expect(() => transportResolver({ P2P_RELAY_TRANSPORT: "nope" }, {})).toThrow(/JSON/);
    expect(() => transportResolver({}, { transport: { "wss://a.example": "http://x" } })).toThrow(/ws/);
  });

  it("tunables fall back to defaults on junk", () => {
    expect(tunables({ P2P_DRAIN_QUIET_MS: "10", P2P_DOC_REFRESH_SEC: "abc" })).toMatchObject({ drainQuietMs: 10, docRefreshSec: 60 });
  });
});

describe("sessions", () => {
  it("parses targets: user, user [ref], user/sid", () => {
    expect(parseTarget("bob")).toEqual({ user: "bob" });
    expect(parseTarget("bob@aaaa-bbbb-cccc-dddd [a1b2c3]")).toEqual({ user: "bob@aaaa-bbbb-cccc-dddd", pick: "a1b2c3" });
    expect(parseTarget("p2p:abc/sess-1")).toEqual({ user: "p2p:abc", pick: "sess-1" });
    expect(parseTarget("bobby/")).toEqual({ user: "bobby/" });
  });

  it("session ids and refs", () => {
    expect(checkSid("0b6c1f0e-uuid.1")).toBe("0b6c1f0e-uuid.1");
    expect(() => checkSid("~contact")).toThrow(CliError);
    expect(() => checkSid("a|b")).toThrow(CliError);
    expect(sessionRef("p2p:x", "s")).toMatch(/^[0-9a-f]{6}$/);
    expect(sessionRef("p2p:x", "s")).not.toBe(sessionRef("p2p:y", "s"));
  });

  it("builds status bodies: path rules, summaryAt kept while unchanged", () => {
    const s = buildStatus({ session: "s", state: "busy", summary: "x", files: ["a/b.ts"], label: "api", repo: "r", branch: "b", mode: "auto" });
    expect(s).toMatchObject({ state: "busy", label: "api", repo: "r", branch: "b", mode: "auto", summary: "x", files: ["a/b.ts"] });
    const again = buildStatus({ session: "s", state: "idle", summary: "x", label: "api" }, s);
    expect(again.summaryAt).toBe(s.summaryAt);
    expect(buildStatus({ session: "s", state: "idle", label: "l", cwd: "/home/me/proj" }).label).toBe("l");
    expect(buildStatus({ session: "s", state: "idle", cwd: "/home/me/proj" }).label).toBe("proj");
    for (const f of ["../x", "/etc/passwd", "a//b", "C:/x", "a/./b"]) expect(() => buildStatus({ session: "s", state: "busy", files: [f] })).toThrow(CliError);
    expect(() => buildStatus({ session: "s", state: "away" })).toThrow(/busy or idle/);
    expect(() => buildStatus({ session: "s", state: "busy", files: Array.from({ length: 26 }, (_, i) => `f${i}`) })).toThrow(/25/);
  });
});

describe("circle links", () => {
  it("round-trips the head and the owner hint; a plain spec link has no hint", () => {
    const ik = generateIdentityKey();
    const head = createCircle(ik, { name: "team", policy: "open" });
    const plain = encodeCircleLink(head, undefined);
    expect(plain).toMatch(/^p2p:\/\/circle\/[A-Za-z0-9_-]+$/);
    expect(parseCircleLink(plain)).toEqual({ head });
    const withHint = encodeCircleLink(head, { doc: "d.o.c", join: "j.o.in" }, true);
    expect(withHint).toMatch(/^https:\/\/ix-infra\.com\/p2p\/c#[A-Za-z0-9_-]+~[A-Za-z0-9_-]+$/);
    expect(parseCircleLink(withHint)).toEqual({ head, hint: { doc: "d.o.c", join: "j.o.in" } });
    // The deprecated web form still parses (older clients printed it); it is never generated.
    const legacy = withHint.replace("https://ix-infra.com/p2p/c#", "https://peer2peer.dev/c#");
    expect(parseCircleLink(legacy)).toEqual({ head, hint: { doc: "d.o.c", join: "j.o.in" } });
    expect(() => parseCircleLink(`${plain}~!!!`)).toThrow(/damaged/);
  });
});

describe("sync chunking", () => {
  it("splits arrays so each chunk stays under the cap", () => {
    const big = "x".repeat(1000);
    const parts = chunkBody({ friendships: Array.from({ length: 30 }, () => big), blocks: ["a"], defaultCircle: null }, 5000);
    expect(parts.length).toBeGreaterThan(5);
    for (const p of parts) expect(JSON.stringify(p).length).toBeLessThan(6000);
    expect(parts.flatMap((p) => (p.friendships as string[]) ?? [])).toHaveLength(30);
    expect(parts.some((p) => "defaultCircle" in p)).toBe(true);
  });

  it("review M2: measures UTF-8 bytes, not characters (non-ASCII petnames)", () => {
    const petnames = Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`p2p:user${i}`, "名前".repeat(30)]));
    const parts = chunkBody({ friendships: Array.from({ length: 20 }, () => "é".repeat(400)), petnames }, 5000);
    for (const p of parts) expect(Buffer.byteLength(JSON.stringify(p), "utf8")).toBeLessThan(5100);
    // The petnames map is split across chunks; merged key by key it is whole again.
    expect(parts.filter((p) => p.petnames).length).toBeGreaterThan(1);
    expect(Object.assign({}, ...parts.map((p) => p.petnames ?? {}))).toEqual(petnames);
  });

  it("review M2: a circle export larger than a chunk is cut into slices that fit, in order", () => {
    const versions = Array.from({ length: 40 }, (_, i) => `v${i}.${"a".repeat(1500)}`);
    const statements = Array.from({ length: 10 }, (_, i) => `s${i}.${"b".repeat(800)}`);
    const parts = splitCircle({ cid: "c_x", versions, statements, joinedByMe: true, myN: 3, removed: ["p2p:r"] }, 8000);
    expect(parts.length).toBeGreaterThan(5);
    for (const p of parts) {
      expect(Buffer.byteLength(JSON.stringify(p), "utf8")).toBeLessThanOrEqual(8000);
      expect(p).toMatchObject({ cid: "c_x", joinedByMe: true, myN: 3, removed: ["p2p:r"] });
    }
    expect(parts.flatMap((p) => p.versions)).toEqual(versions);
    expect(parts.flatMap((p) => p.statements)).toEqual(statements);
  });
});

describe("watch filtering", () => {
  const ev = (n: number, extra: Record<string, unknown> = {}) => ({ n, id: `e${n}`, at: n, kind: "p2p.message", data: { text: "t" }, ...extra });
  it("prints own-session and addressed events, unclaimed peer events, and control events after the cursor", () => {
    const c = { n: 2, start: 5 };
    expect(eventFor(ev(1, { toSession: "s" }), "s", "me", c)).toBe(false); // already printed
    expect(eventFor(ev(3, { toSession: "s" }), "s", "me", c)).toBe(true); // before start, but addressed to us
    expect(eventFor(ev(4), "s", "me", c)).toBe(false); // control event older than the cursor's start
    expect(eventFor(ev(6, { toSession: "other" }), "s", "me", c)).toBe(false);
    expect(eventFor(ev(7, { own: "peer", sid: "x" }), "s", "me", c)).toBe(true); // unclaimed peer session
    expect(eventFor(ev(8, { own: "me", sid: "x" }), "s", "me", c)).toBe(false); // another of my sessions
    expect(eventFor(ev(9), "s", "me", c)).toBe(true);
    expect(JSON.parse(eventLine(ev(9, { toSession: "s" }) as never))).toEqual({ kind: "p2p.message", id: "e9", at: 9, text: "t", toSession: "s" });
  });
});

describe("avatars", () => {
  const png = (n: number) => new Uint8Array([0x89, 0x50, 0x4e, 0x47, ...new Array(n).fill(7)]);
  it("turns a small image into a data: URI, refuses big or non-image files", async () => {
    expect(await avatarValue("https://example.com/a.png")).toBe("https://example.com/a.png");
    expect(await avatarValue("x.png", async () => png(100))).toMatch(/^data:image\/png;base64,/);
    await expect(avatarValue("x.png", async () => png(4000))).rejects.toThrow(/4 KiB/);
    await expect(avatarValue("x.svg", async () => new TextEncoder().encode("<svg/>"))).rejects.toThrow(/SVG is not allowed/);
    await expect(avatarValue("missing.png", async () => Promise.reject(new Error("ENOENT")))).rejects.toThrow(/readable image/);
  });
});
