// Copyright 2026 Ix Infrastructure Inc.
//
// `p2p doctor`: integration tests over in-process relays (a friend who has
// shared no session, then one who has; a relay that refuses connections and
// one that never answers), plus the output contract: ✓ ✗ ?, a fix per
// problem, nothing secret, bounded time.

import { createHash } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer, type Server } from "node:net";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createDeviceCert, createIdentityDoc, generateDeviceKeysV3, generateIdentityKey, nowSec, peekIdentityDoc, addIdentityVersion } from "@peer2peer/core/v3";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { clockVerdict, formatDoctor, modVersions, SKEW_FAIL_SEC, SKEW_OK_SEC, summarize, type Check } from "../doctor.js";
import { main } from "../cli.js";
import { VERSION } from "../version.js";
import { alongside, startRelay, User, type TestRelay } from "./harness.js";

/** The ext-ix copy the Claude mod ships (what it passes as P2P_EXTENSION_PATH). */
const EXT_DIR = join(fileURLToPath(new URL(".", import.meta.url)), "../../../../mods/claude/peer2peer/ext");

const R = "wss://doctor-one.test/v3";
const DEAD = "wss://doctor-dead.test/v3";
const HOLE = "wss://doctor-hole.test/v3";

let relay: TestRelay;
let hole: Server;
let holePort = 0;
const holeSockets = new Set<import("node:net").Socket>();
let deadPort = 0;
let ann: User;
let ben: User;
let cid = "";
const ids: Record<string, string> = {};
const homes: string[] = [];

const byId = (checks: Check[], id: string) => checks.find((c) => c.id === id);

/** Every file and directory under `dir`: path, kind, size, mtime and contents. Any write changes it. */
function hashTree(dir: string): string {
  const h = createHash("sha256");
  const walk = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name);
      const st = lstatSync(p);
      h.update(`${p.slice(dir.length)}\0${st.isDirectory() ? "d" : "f"}\0${st.size}\0${st.mtimeMs}\0`);
      if (st.isDirectory()) walk(p);
      else h.update(readFileSync(p));
    }
  };
  h.update(String(lstatSync(dir).mtimeMs));
  walk(dir);
  return h.digest("hex");
}

describe("p2p doctor", () => {
  beforeAll(async () => {
    relay = await startRelay(R);
    // A port nothing listens on (refused), and a server that accepts TCP and never answers.
    const tmp = createServer();
    await new Promise<void>((r) => tmp.listen(0, "127.0.0.1", () => r()));
    deadPort = (tmp.address() as { port: number }).port;
    await new Promise<void>((r) => tmp.close(() => r()));
    hole = createServer((sock) => {
      holeSockets.add(sock);
      sock.on("close", () => holeSockets.delete(sock));
    });
    await new Promise<void>((r) => hole.listen(0, "127.0.0.1", () => r()));
    holePort = (hole.address() as { port: number }).port;
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3`, [DEAD]: `ws://127.0.0.1:${deadPort}/v3`, [HOLE]: `ws://127.0.0.1:${holePort}/v3` };
    // Generous bounds for the healthy path (a loaded test machine must not turn ✓ into ✗); the
    // unreachable cases below use short ones of their own.
    const roomy = { P2P_DOCTOR_TIMEOUT_MS: "8000", P2P_CONNECT_TIMEOUT_MS: "8000" };
    ann = new User("ann", t, roomy);
    ben = new User("ben", t, roomy);
    ids.ann = (await ann.ok(["init", "--name", "ann", "--relay", R, "--yes"])).userId;
    cid = (await ann.ok(["circle", "create", "ix-team"])).cid;
    await ann.ok(["circle", "default", cid]);
    const inv = await ann.ok(["invite", "ben"]);
    // Ann's client handles the accept while Ben waits (as a running mod would).
    const j = await alongside(ben.run(["join", "--confirmed", inv.code, "--wait", "12", "--name", "ben"]), () => ann.ok(["invites"]));
    expect(j.code).toBe(0);
    ids.ben = j.json.created.userId;
    expect(j.json.circle).toMatchObject({ cid, status: "joined" });
    await ann.ok(["friends"]);
  }, 60_000);

  afterAll(async () => {
    await relay?.close();
    // The black hole never answers, so the server side of abandoned dials stays open until destroyed.
    for (const s of holeSockets) s.destroy();
    await new Promise<void>((r) => (hole ? hole.close(() => r()) : r()));
    ann?.cleanup();
    ben?.cleanup();
    for (const h of homes) rmSync(h, { recursive: true, force: true });
  });

  it("this device: identity, relay, published document, clock, default circle", async () => {
    const r = await ann.ok(["doctor"]);
    expect(r.scope).toBe("device");
    expect(byId(r.checks, "identity")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, "document")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, `relay:${R}`)).toMatchObject({ status: "ok", detail: expect.stringMatching(/reachable \(\d+ ms to connect, \d+ ms round trip\); this device's mailbox works/) });
    expect(byId(r.checks, `published:${R}`)).toMatchObject({ status: "ok", detail: expect.stringMatching(/published \(version \d+, the current one\)/) });
    expect(byId(r.checks, "clock")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, "default-circle")).toMatchObject({ status: "ok", detail: expect.stringContaining('"ix-team"') });
    // Nothing live yet: unknown, with what would tell.
    expect(byId(r.checks, "shared")).toMatchObject({ status: "unknown", fix: expect.any(String) });
    expect(byId(r.checks, "publisher")).toMatchObject({ status: "unknown" });
    expect(byId(r.checks, "version")).toMatchObject({ status: "unknown" });
    expect(r.summary).toEqual(summarize(r.checks));
    // Every problem has a fix; nothing secret (no JWS: keys, caps, certificates, documents).
    for (const c of r.checks as Check[]) if (c.status !== "ok") expect(c.fix, c.id).toBeTruthy();
    expect(JSON.stringify(r)).not.toMatch(/eyJ[A-Za-z0-9_-]{10}/);
  });

  it("a friend with no shared session: ✗ with the fix naming the circle and the real /peers command", async () => {
    const r = await ann.ok(["doctor", ids.ben]);
    expect(r.scope).toBe("user");
    expect(r.user).toMatchObject({ userId: ids.ben, address: expect.stringMatching(/^ben@/) });
    expect(byId(r.checks, "device")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, "friendship")).toMatchObject({ status: "ok", detail: expect.stringMatching(/friends since .*you also share "ix-team"/) });
    expect(byId(r.checks, "their-document")).toMatchObject({ status: "ok", detail: expect.stringContaining("fetched just now") });
    expect(byId(r.checks, "relays")).toMatchObject({ status: "ok", detail: expect.stringContaining(`you share "${R}"`) });
    expect(byId(r.checks, "cap-ours")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, "cap-theirs")).toMatchObject({ status: "ok" });
    expect(byId(r.checks, "blocked")).toMatchObject({ status: "ok" });
    const s = byId(r.checks, "their-sessions");
    expect(s).toMatchObject({ status: "fail" });
    expect(s?.fix).toContain(`they haven't shared any session with "ix-team"`);
    expect(s?.fix).toContain(`/peers project share ${cid}`);
    // By name too, and in words.
    const human = await ann.run(["doctor", "ben"], { json: false });
    expect(human.code).toBe(0);
    expect(human.out).toMatch(/^p2p doctor: can you see ben@/);
    expect(human.out).toMatch(/✓ friendship: friends since/);
    expect(human.out).toMatch(/✗ their sessions: no status from any of their sessions has reached you/);
    expect(human.out).toMatch(/\n {4}fix: they haven't shared any session with "ix-team"/);
    expect(human.out).not.toMatch(/eyJ[A-Za-z0-9_-]{10}/);
  }, 30_000);

  it("once the friend shares a live session, it shows as ✓ (and their doctor sees the publisher)", async () => {
    // Ben's code join made the circle his default; his project is his to share (projects.ts).
    await ben.share(cid);
    await ben.ok(["status", "--session", "bs1", "--state", "busy", "--label", "api"]);
    await ann.ok(["ls"]);
    const r = await ann.ok(["doctor", "ben"]);
    const row = r.checks.find((c: Check) => c.id === "their-session:bs1");
    expect(row).toMatchObject({ status: "ok", detail: expect.stringMatching(/live \(busy, .*\), shared with circle "ix-team"/) });
    expect(byId(r.checks, "received")).toMatchObject({ status: "ok" });
    const mine = await ben.ok(["doctor"]);
    expect(byId(mine.checks, "publisher")).toMatchObject({ status: "ok" });
    expect(byId(mine.checks, "shared:bs1")).toMatchObject({ status: "ok", detail: expect.stringContaining("1 can see it (ann@") });
  }, 30_000);

  it("read-only: P2P_HOME is byte-for-byte unchanged, and a queued envelope is still delivered afterwards", async () => {
    // A message waits in Ben's mailbox: Ann's session is shared with him, he hasn't connected since.
    await ann.ok(["session", "roster", "as1", "--add", ids.ben]);
    const sent = await ann.ok(["send", "--from-session", "as1", "--to", ids.ben, "still", "here?"]);
    expect(sent.delivered).toBe(true);
    // Ben has the Ix extension enabled (as the mod runs p2p: its bundled copy, config opt-in), never
    // loaded yet: loading it would record <home>/extension-locations.json.
    writeFileSync(join(ben.home, "config.json"), JSON.stringify({ extensions: ["ix"] }));
    const extEnv = { ...ben.env, P2P_EXTENSION_PATH: EXT_DIR, P2P_EXTENSIONS: "config" };
    const asBen = async (args: string[]) => {
      const out: string[] = [];
      const code = await main([...args, "--json"], { env: extEnv, io: { out: (l) => out.push(l), err: () => {} } });
      process.exitCode = 0;
      expect(code).toBe(0);
      return JSON.parse(out.at(-1) ?? "null");
    };
    const benBefore = hashTree(ben.home);
    const annBefore = hashTree(ann.home);
    const self = await asBen(["doctor"]);
    expect(byId(self.checks, `relay:${R}`)?.detail).toMatch(/[1-9]\d* envelopes? queued for this device/);
    const about = await asBen(["doctor", "ann"]);
    expect(byId(about.checks, "their-document")).toMatchObject({ status: "ok" });
    await ann.ok(["doctor", ids.ben]);
    expect(hashTree(ben.home)).toBe(benBefore);
    expect(hashTree(ann.home)).toBe(annBefore);
    // The setup is real: any other command loads the extension (and records where from).
    expect((await asBen(["extensions"])).extensions.map((e: { ns: string }) => e.ns)).toContain("ix");
    expect(existsSync(join(ben.home, "extension-locations.json"))).toBe(true);
    // Never acked: Ben's next real command still gets it.
    // (It goes into Ben's live session bs1, shared with the circle: a circle-mate's message, rule
    // "circle", which inbound.ts used to send to the circle handler and drop.)
    const lines = await ben.watch("bs1", 2000);
    expect(lines.find((e) => e.kind === "p2p.message")).toMatchObject({ text: "still here?", own: ids.ben, sid: "bs1", rule: "circle" });
  }, 60_000);

  it("a peer's forked document listing many relays: at most 5 are probed, and they're shown as quoted peer data", async () => {
    // A counting HTTP server stands in for every relay the peer lists.
    let hits = 0;
    const counter = createHttpServer((_req, res) => {
      hits++;
      res.writeHead(404, { "content-type": "application/json" }).end("{}");
    });
    await new Promise<void>((r) => counter.listen(0, "127.0.0.1", () => r()));
    const cport = (counter.address() as { port: number }).port;
    try {
      // "mal": one key-holding device; version 1, then 10 competing version-2 branches of 5 relays each.
      const ik = generateIdentityKey();
      const dev = generateDeviceKeysV3(ik.userId);
      const cert = createDeviceCert(ik, { ...dev, label: "mal" });
      const base = { name: "mal", devices: [dev.did], keyholders: [dev.did], by: dev.did, certs: [cert] };
      const v1 = createIdentityDoc(ik, { ...base, ver: 1, prev: null, relays: [R], iat: nowSec() - 120 });
      const many: string[] = [];
      const forks = Array.from({ length: 10 }, (_, i) => {
        const relays = Array.from({ length: 5 }, (_, j) => `wss://m${i}-${j}.doctor.test/v3`);
        many.push(...relays);
        return createIdentityDoc(ik, { ...base, ver: 2, prev: peekIdentityDoc(v1).hash, relays, iat: nowSec() - 60 + i });
      });
      const t = { [R]: `ws://127.0.0.1:${relay.port}/v3`, ...Object.fromEntries(many.map((r) => [r, `ws://127.0.0.1:${cport}/v3`])) };
      const eve = new User("eve", t, { P2P_DOCTOR_TIMEOUT_MS: "3000", P2P_CONNECT_TIMEOUT_MS: "3000" });
      homes.push(eve.home);
      await eve.ok(["init", "--name", "eve", "--relay", R, "--yes"]);
      const app = await eve.app();
      for (const d of [v1, ...forks]) await addIdentityVersion(app.store, d);
      const view = await app.view(ik.userId);
      expect(view?.forked).toBe(true);
      expect(view?.relays.length).toBeGreaterThanOrEqual(50);
      const r = await eve.ok(["doctor", ik.userId]);
      const relaysCheck = byId(r.checks, "relays");
      expect(relaysCheck).toBeDefined();
      const shown = relaysCheck!.detail.match(/"wss:\/\/[^"]+"/g) ?? [];
      expect(shown.length).toBeLessThanOrEqual(5);
      // Probes (≤ 5) plus the identity refresh (≤ 5 tips; no chain walk on 404s): never one per listed relay.
      expect(hits).toBeLessThanOrEqual(12);
    } finally {
      await new Promise<void>((r) => counter.close(() => r()));
    }
  }, 60_000);

  it("an unknown user, a blocked one", async () => {
    const r = await ann.ok(["doctor", "nobody-here"]);
    expect(r.checks).toEqual([expect.objectContaining({ id: "user", status: "fail", fix: expect.stringContaining("p2p invite") })]);
    await ann.ok(["block", ids.ben]);
    const b = await ann.ok(["doctor", ids.ben]);
    expect(byId(b.checks, "blocked")).toMatchObject({ status: "fail", fix: `\`p2p unblock ${ids.ben}\`` });
    await ann.ok(["unblock", ids.ben]);
  }, 30_000);

  it("unreachable relays (refused, and one that never answers): ✗ with a fix, within the bound", async () => {
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3`, [DEAD]: `ws://127.0.0.1:${deadPort}/v3`, [HOLE]: `ws://127.0.0.1:${holePort}/v3` };
    const cy = new User("cy", t, { P2P_DOCTOR_TIMEOUT_MS: "800" });
    homes.push(cy.home);
    await cy.ok(["init", "--name", "cy", "--relay", R, "--yes"]);
    // Point the identity at two relays that can't be reached (as if the network blocked them).
    const app = await cy.app();
    await app.load();
    await app.updateSelf((s) => ({ ...s, relays: [DEAD, HOLE] }));
    const t0 = Date.now();
    const r = await cy.ok(["doctor"]);
    const took = Date.now() - t0;
    expect(byId(r.checks, `relay:${DEAD}`)).toMatchObject({ status: "fail", detail: expect.stringMatching(/unreachable: can't reach .*connection refused/), fix: expect.stringContaining("p2p relays add") });
    expect(byId(r.checks, `relay:${HOLE}`)).toMatchObject({ status: "fail", detail: expect.stringMatching(/unreachable/), fix: expect.stringContaining("firewall") });
    expect(byId(r.checks, `published:${DEAD}`)).toMatchObject({ status: "unknown" });
    expect(byId(r.checks, "clock")).toMatchObject({ status: "unknown" });
    // Bounded: a few timeouts in parallel, never the 60 s command deadline.
    expect(took).toBeLessThan(15_000);
    // About a user too: still bounded, still an answer.
    const u = await cy.ok(["doctor", ids.ann]);
    expect(byId(u.checks, "device")).toMatchObject({ status: "fail", detail: expect.stringContaining("relay") });
  }, 60_000);

  it("no identity yet: says how to set up, exit 0", async () => {
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const none = new User("none", t, { P2P_DOCTOR_TIMEOUT_MS: "800", P2P_DEFAULT_RELAYS: R });
    homes.push(none.home);
    const r = await none.run(["doctor"]);
    expect(r.code).toBe(0);
    expect(byId(r.json.checks, "identity")).toMatchObject({ status: "fail", fix: expect.stringContaining("/peers setup") });
    expect(byId(r.json.checks, `relay:${R}`)).toMatchObject({ status: "ok" });
  });

  it("versions: the mod's bundled p2p vs this one", async () => {
    const root = mkdtempSync(join(tmpdir(), "p2p-mod-"));
    homes.push(root);
    mkdirSync(join(root, ".claude-plugin"));
    mkdirSync(join(root, "bin"));
    writeFileSync(join(root, ".claude-plugin", "plugin.json"), JSON.stringify({ name: "peer2peer", version: "0.1.0" }));
    writeFileSync(join(root, "bin", "p2p.mjs"), 'var BRIDGE_VERSION = "9.9.9";\nvar VERSION = "0.0.9";\n');
    expect(await modVersions(root)).toEqual({ plugin: "0.1.0", bundled: "0.0.9" });
    const t = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
    const dee = new User("dee", t, { P2P_DOCTOR_TIMEOUT_MS: "800", P2P_MOD_ROOT: root });
    homes.push(dee.home);
    const r = await dee.ok(["doctor"]);
    expect(byId(r.checks, "version")).toMatchObject({ status: "fail", detail: `this p2p is ${VERSION} but the mod (0.1.0) bundles 0.0.9`, fix: expect.stringContaining("P2P_BIN") });
    writeFileSync(join(root, "bin", "p2p.mjs"), `var VERSION = "${VERSION}";\n`);
    expect(byId((await dee.ok(["doctor"])).checks, "version")).toMatchObject({ status: "ok" });
  });

  it("formats ✓ ✗ ? with fixes", () => {
    const checks: Check[] = [
      { id: "a", status: "ok", title: "relay x", detail: "reachable" },
      { id: "b", status: "fail", title: "default circle", detail: "none", fix: "p2p circle default <cid>" },
      { id: "c", status: "unknown", title: "watch", detail: "no cursor", fix: "start the mod" },
    ];
    const s = formatDoctor({ scope: "device", version: "0.1.0", checks, summary: summarize(checks) });
    expect(s.split("\n")).toEqual([
      "p2p doctor: this device",
      "",
      "✓ relay x: reachable",
      "✗ default circle: none",
      "    fix: p2p circle default <cid>",
      "? watch: no cursor",
      "    to tell: start the mod",
      "",
      "1 ✓  1 ✗  1 ?",
    ]);
  });
});

describe("doctor clock check (skew vs the protocol's limit)", () => {
  const at = (sec: number) => clockVerdict([{ relay: R, sec }]);

  it("the limit is core's DEFAULT_SKEW_SEC (300 s), not the old 60 s", () => {
    expect(SKEW_OK_SEC).toBe(30);
    expect(SKEW_FAIL_SEC).toBe(300);
  });

  it("✓ under 30 s, either way", () => {
    expect(at(0)).toMatchObject({ status: "ok", detail: `within 1s of ${R}` });
    expect(at(29)).toMatchObject({ status: "ok" });
    expect(at(-29)).toMatchObject({ status: "ok" });
    expect(at(29).fix).toBeUndefined();
  });

  it("? (a warning) from 30 s up to 300 s: it still works, so never ✗", () => {
    for (const s of [30, 61, 120, 299, 300, -45, -300]) {
      const c = at(s);
      expect(c.status, `${s}s`).toBe("unknown");
      expect(c.detail).toMatch(/still within the protocol's 300s \(5-minute\) limit/);
      expect(c.fix).toMatch(/automatic time/);
    }
    expect(at(61).detail).toBe(
      `61s ahead of ${R}: still within the protocol's 300s (5-minute) limit, but 239s more drift and relays and peers will reject what this device signs (sooner with a peer whose clock is off the other way: the two add up)`,
    );
    expect(at(-45).detail).toMatch(/^45s behind /);
  });

  it("✗ only past 300 s", () => {
    for (const s of [301, -301, 3600]) expect(at(s).status, `${s}s`).toBe("fail");
    expect(at(400).detail).toBe(`400s ahead of ${R}: past the protocol's 300s (5-minute) limit, so relays and peers reject what this device signs`);
  });

  it("the worst relay decides; none answering is ?", () => {
    const c = clockVerdict([
      { relay: "wss://a.test/v3", sec: 2 },
      { relay: "wss://b.test/v3", sec: -400 },
    ]);
    expect(c).toMatchObject({ status: "fail", detail: expect.stringMatching(/^400s behind wss:\/\/b\.test\/v3/) });
    expect(clockVerdict([{ relay: "wss://a.test/v3", sec: 3 }, { relay: "wss://b.test/v3", sec: 1 }]).detail).toBe("within 3s of your relays (worst: wss://a.test/v3)");
    expect(clockVerdict([])).toMatchObject({ status: "unknown", detail: "no relay answered with its time" });
  });

  it("a warning doesn't fail the device summary", () => {
    expect(summarize([at(120)] as Check[])).toMatchObject({ fail: 0, unknown: 1 });
  });
});
