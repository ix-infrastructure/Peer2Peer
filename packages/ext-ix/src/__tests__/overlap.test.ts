// Copyright 2026 Ix Infrastructure Inc.
//
// Footprint overlap (SPEC.md §9): every tier, both directions, plain, hashed
// and mixed bodies, other repositories, stable keys, and messages that name
// only what this side knows.

import { describe, expect, it } from "vitest";
import { assembleFootprint, type FootprintBody, type RawActor } from "../footprint.js";
import { deriveNameKey } from "../hmac.js";
import { computeOverlaps as computeOverlapsRaw, type OverlapInput, type OverlapPeer } from "../overlap.js";

// Most cases: we publish plain names and bob is in our session's audience (each test overrides as it needs).
const computeOverlaps = (i: OverlapInput) => computeOverlapsRaw({ publishedNames: "plain", statusAudience: ["p2p:bob"], ...i });

const REPO = { remote: "github.com/acme/api", branch: "main" };
const KEY = deriveNameKey(REPO.remote, "a".repeat(40));

const actor = (a: string, o: Partial<RawActor> = {}): RawActor => ({ a, graph: "base", risk: "medium", files: [], symbols: [], ring1Files: [], ring1Symbols: [], components: [], ...o });
const body = (actors: RawActor[], o: { hashed?: boolean; repo?: typeof REPO } = {}): FootprintBody =>
  assembleFootprint({ repo: o.repo ?? REPO, at: 1, seq: 1, actors, ...(o.hashed ? { key: KEY } : {}) }).body;
const peer = (b: FootprintBody, o: Partial<OverlapPeer> = {}): OverlapPeer => ({ own: "p2p:bob", sid: "bs1", ref: "b0b0b0", address: "bob@bbbb-bbbb", body: b, ...o });

// Me: changing SessionStore.refresh in session.ts; handleLogin calls it; jobs/sync.ts is two hops away.
const ME = actor("main", {
  risk: "high",
  files: ["src/auth/session.ts", "src/billing/invoice.ts"],
  symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }, { k: "src/billing/invoice.ts#total", kind: "function" }],
  ring1Files: [{ f: "src/api/login.ts", rel: "call" }, { f: "src/web/app.ts", rel: "import" }],
  ring1Symbols: [{ k: "src/api/login.ts#handleLogin", rel: "call" }],
  ring2Files: ["src/jobs/sync.ts"],
  components: [{ n: "auth", kind: "subsystem", count: 3 }],
});

describe("tiers", () => {
  it("T1 same symbol: high, both ways", () => {
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("main", { files: ["src/auth/session.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }] })]))] });
    expect(r.overlaps.map((o) => [o.tier, o.severity, o.direction])).toContainEqual(["same-symbol", "high", "both"]);
    const t1 = r.overlaps.find((o) => o.tier === "same-symbol")!;
    expect(t1.message).toBe("POSSIBLE CONFLICT (high, same symbol) with bob@bbbb-bbbb: you both change src/auth/session.ts#SessionStore.refresh");
    // No T3 alongside T1 for the same file.
    expect(r.overlaps.some((o) => o.tier === "same-file")).toBe(false);
  });

  it("T2 mine affects theirs: they edit a caller of what I change (high: it calls it and my risk is high)", () => {
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("a2", { wt: true, files: ["src/api/login.ts"], symbols: [{ k: "src/api/login.ts#handleLogin", kind: "function" }] })]))] });
    const o = r.overlaps.find((x) => x.tier === "depends")!;
    expect(o).toMatchObject({ severity: "high", direction: "mine-affects-theirs", mine: "main", theirs: "a2", via: { rel: "call" } });
    expect(o.message).toBe(`POSSIBLE CONFLICT (high, depends) with bob@bbbb-bbbb [agent a2, worktree]: your change affects src/api/login.ts#handleLogin they're editing (it calls it) (unmerged, agent worktree)`);
  });

  it("T2 theirs affects mine: I edit what depends on their change; file level when there are no ring symbols", () => {
    const r = computeOverlaps({ mine: body([actor("a1", { files: ["src/jobs/sync.ts"] })]), peers: [peer(body([actor("main", { files: ["lib/db.ts"], ring1Files: [{ f: "src/jobs/sync.ts", rel: "import" }] })]))] });
    expect(r.overlaps).toHaveLength(1);
    expect(r.overlaps[0]).toMatchObject({ tier: "depends", severity: "medium", direction: "theirs-affects-mine", mine: "a1" });
    expect(r.overlaps[0].message).toBe("POSSIBLE CONFLICT (medium, depends) with bob@bbbb-bbbb: their change affects src/jobs/sync.ts you're editing (it imports their change) (your agent a1)");
  });

  it("T3 same file: medium, different symbols", () => {
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("main", { files: ["src/billing/invoice.ts"], symbols: [{ k: "src/billing/invoice.ts#tax", kind: "function" }] })]))] });
    expect(r.overlaps.map((o) => [o.tier, o.severity])).toEqual([["same-file", "medium"]]);
    expect(r.overlaps[0].message).toMatch(/you both edit src\/billing\/invoice\.ts \(different symbols\)$/);
  });

  it("T4 same area: low, only without T1-T3", () => {
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("main", { files: ["src/auth/oauth.ts"], components: [{ n: "auth", count: 1 }] })]))] });
    expect(r.overlaps.map((o) => [o.tier, o.severity, o.direction])).toEqual([["same-area", "low", "both"]]);
  });

  it("T5 transitive: low, both directions, only without T1-T4", () => {
    const mine = computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("main", { files: ["src/jobs/sync.ts"] })]))] });
    expect(mine.overlaps.map((o) => [o.tier, o.severity, o.direction])).toEqual([["transitive", "low", "mine-affects-theirs"]]);
    const theirs = computeOverlaps({ mine: body([actor("main", { files: ["src/x.ts"] })]), peers: [peer(body([actor("main", { files: ["lib/y.ts"], ring2Files: ["src/x.ts"] })]))] });
    expect(theirs.overlaps.map((o) => o.direction)).toEqual(["theirs-affects-mine"]);
  });

  it("no overlap: nothing", () => {
    expect(computeOverlaps({ mine: body([ME]), peers: [peer(body([actor("main", { files: ["docs/x.md"] })]))] }).overlaps).toEqual([]);
  });
});

describe("names: plain, hashed, mixed", () => {
  const theirs = [actor("main", { files: ["src/api/login.ts"], symbols: [{ k: "src/api/login.ts#handleLogin", kind: "function" }, { k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }] })];
  const plain = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs))] });

  it("hashed both sides: the same overlaps, matched on tokens; model lines name nothing", () => {
    const hashed = computeOverlaps({ mine: body([ME], { hashed: true }), peers: [peer(body(theirs, { hashed: true }))], key: KEY });
    expect(hashed.overlaps.map((o) => [o.tier, o.direction])).toEqual(plain.overlaps.map((o) => [o.tier, o.direction]));
    expect(hashed.overlaps.map((o) => o.message).join("\n")).not.toMatch(/src\/|h:|SessionStore|handleLogin/);
    expect(hashed.overlaps.find((o) => o.tier === "same-symbol")!.message).toMatch(/you both change a symbol you are changing \(hashed: names stay private\)$/);
    expect(hashed.overlaps.every((o) => !o.named)).toBe(true);
  });

  it("mixed: my plain names, their hashed body: matched; the model's lines stay generic, the person's detail names mine", () => {
    const mixed = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs, { hashed: true }))], key: KEY });
    expect(mixed.overlaps.map((o) => [o.tier, o.direction])).toEqual(plain.overlaps.map((o) => [o.tier, o.direction]));
    expect(mixed.overlaps.map((o) => o.message).join("\n")).not.toMatch(/src\/|h:|SessionStore|handleLogin/);
    expect(mixed.overlaps.map((o) => o.detail)).toEqual(plain.overlaps.map((o) => o.detail));
    // A file my own status already shares in the clear may be named (the peer sees it anyway).
    const withStatus = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs, { hashed: true }))], key: KEY, statusFiles: ["src/auth/session.ts"], statusAudience: ["p2p:bob"] });
    expect(withStatus.overlaps.find((o) => o.tier === "same-symbol")!.message).toMatch(/you both change a symbol you are changing in src\/auth\/session\.ts \(hashed: names stay private\)$/);
    expect(withStatus.overlaps.map((o) => o.message).join("\n")).not.toMatch(/SessionStore|handleLogin|src\/api/);
  });

  it("H1: a peer echoing my hashed tokens (ring 1 included) learns no name from any model line", () => {
    // They hold only my published, hashed footprint, and replay its tokens as their own changes.
    const myHashed = body([ME], { hashed: true });
    const echo: FootprintBody = {
      ...myHashed,
      actors: myHashed.actors.map((a) => ({ ...a, changed: { files: [...a.changed.files, ...a.ring1.files.map((x) => x.f)], symbols: [...a.changed.symbols, ...a.ring1.symbols.map((x) => ({ k: x.k, kind: "function" }))] } })),
    };
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(echo)], key: KEY });
    expect(r.overlaps.length).toBeGreaterThan(0);
    const lines = r.overlaps.map((o) => o.message).join("\n");
    for (const name of ["src/", "SessionStore", "refresh", "handleLogin", "invoice", "login", "auth"]) expect(lines).not.toContain(name);
    expect(r.overlaps.every((o) => o.message.endsWith("(hashed: names stay private)") || o.message.includes("(hashed: names stay private) ("))).toBe(true);
  });

  it("L1: a status file is named only to a peer my status reaches", () => {
    const outside = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs, { hashed: true }))], key: KEY, statusFiles: ["src/auth/session.ts"], statusAudience: ["p2p:someone-else"] });
    expect(outside.overlaps.map((o) => o.message).join("\n")).not.toContain("src/");
    const none = computeOverlapsRaw({ mine: body([ME]), peers: [peer(body(theirs, { hashed: true }))], key: KEY, statusFiles: ["src/auth/session.ts"] });
    expect(none.overlaps.map((o) => o.message).join("\n")).not.toContain("src/");
  });

  it("M1: a peer publishing guesses in plain names gets no confirmation while I publish hashed names", () => {
    // Their "plain" body is a list of guesses at my names; one hits.
    const guesses = [actor("main", { files: ["src/auth/session.ts", "src/auth/token.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }, { k: "src/auth/token.ts#Token.rotate", kind: "method" }] })];
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body(guesses))], key: KEY, publishedNames: "hmac" });
    expect(r.overlaps.length).toBeGreaterThan(0);
    const lines = r.overlaps.map((o) => o.message).join("\n");
    expect(lines).not.toMatch(/SessionStore|src\//);
    expect(r.overlaps.every((o) => !o.named && o.message.includes("(hashed: names stay private)"))).toBe(true);
    // Once I publish plain names for this audience, their names (which they hold) may appear.
    const open = computeOverlaps({ mine: body([ME]), peers: [peer(body(guesses))], publishedNames: "plain" });
    expect(open.overlaps.find((o) => o.tier === "same-symbol")!.message).toContain("SessionStore.refresh");
  });

  it("M1: a guessing peer outside my session's audience gets no confirmation, even when I publish plain names", () => {
    const guesses = [actor("main", { files: ["src/auth/session.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }] })];
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body(guesses))], publishedNames: "plain", statusAudience: ["p2p:someone-else"] });
    expect(r.overlaps.length).toBeGreaterThan(0);
    expect(r.overlaps.map((o) => o.message).join("\n")).not.toMatch(/SessionStore|src\//);
    // And without publishedNames: hashed by default.
    const d = computeOverlapsRaw({ mine: body([ME]), peers: [peer(body(guesses))], statusAudience: ["p2p:bob"] });
    expect(d.overlaps.every((o) => !o.named)).toBe(true);
  });

  it("a genuine plain-plain overlap still names the symbol (they hold the name)", () => {
    expect(plain.overlaps.find((o) => o.tier === "same-symbol")!.message).toMatch(/you both change src\/auth\/session\.ts#SessionStore\.refresh$/);
    expect(plain.overlaps.every((o) => o.named)).toBe(true);
  });

  it("mixed the other way: my hashed body, their plain one", () => {
    const r = computeOverlaps({ mine: body([ME], { hashed: true }), peers: [peer(body(theirs))], key: KEY });
    expect(r.overlaps.map((o) => [o.tier, o.direction])).toEqual(plain.overlaps.map((o) => [o.tier, o.direction]));
  });

  it("mixed without the key: skipped, not guessed", () => {
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs, { hashed: true }))] });
    expect(r.overlaps).toEqual([]);
    expect(r.skipped[0].reason).toMatch(/no repository key/);
  });

  it("another repository, or another key (a fork): no comparison", () => {
    const other = computeOverlaps({ mine: body([ME]), peers: [peer(body(theirs, { repo: { remote: "github.com/acme/web", branch: "main" } }))] });
    expect(other.overlaps).toEqual([]);
    expect(other.skipped[0].reason).toBe("another repository");
    const fork = deriveNameKey(REPO.remote, "b".repeat(40));
    const forked = assembleFootprint({ repo: REPO, at: 1, seq: 1, actors: theirs, key: fork }).body;
    const r = computeOverlaps({ mine: body([ME]), peers: [peer(forked)], key: KEY });
    expect(r.overlaps).toEqual([]);
    expect(r.skipped[0].reason).toMatch(/another repository key/);
  });
});

describe("keys and modifiers", () => {
  it("M1: dedupe ignores the peer's session and agent ids (a peer cycling them gets one line)", () => {
    const same = (a: string) => actor(a, { files: ["src/auth/session.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }] });
    const r = computeOverlaps({
      mine: body([ME]),
      peers: [peer(body([same("a1"), same("a2"), same("a3"), same("a4")])), peer(body([same("main"), same("a9")]), { sid: "bs2", ref: "b1b1b1" })],
    });
    expect(r.overlaps.filter((o) => o.tier === "same-symbol")).toHaveLength(1);
    expect(r.overlaps[0].key).toBe(JSON.stringify(["p2p:bob", "same-symbol", "both", "src/auth/session.ts#SessionStore.refresh"]));
  });

  it("each overlap's key is stable across recomputation and changes with the entry", () => {
    const p = peer(body([actor("main", { files: ["src/auth/session.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.refresh", kind: "method" }] })]));
    const a = computeOverlaps({ mine: body([ME]), peers: [p] }).overlaps.map((o) => o.key);
    const b = computeOverlaps({ mine: body([ME]), peers: [p] }).overlaps.map((o) => o.key);
    expect(a).toEqual(b);
    const q = peer(body([actor("main", { files: ["src/auth/session.ts"], symbols: [{ k: "src/auth/session.ts#SessionStore.revoke", kind: "method" }] })]));
    expect(computeOverlaps({ mine: body([ME]), peers: [q] }).overlaps.map((o) => o.key)).not.toEqual(a);
  });

  it("another branch (plain peers), and approximate footprints, are said; lines stay within 240 characters", () => {
    const long = "x".repeat(150);
    const p = peer(body([actor("main", { coarse: true, files: [`src/${long}.ts`] })], { repo: { remote: REPO.remote, branch: "feature/y" } }), { address: `bob@${"b".repeat(100)}` });
    const r = computeOverlaps({ mine: body([actor("main", { files: [`src/${long}.ts`] })]), peers: [p] });
    expect(r.overlaps[0].message).toMatch(/… \(on branch feature\/y; approximate\)$/);
    expect([...r.overlaps[0].message].length).toBeLessThanOrEqual(240);
  });
});
