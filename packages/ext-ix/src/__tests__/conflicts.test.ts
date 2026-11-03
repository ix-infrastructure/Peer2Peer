// Copyright 2026 Ix Infrastructure Inc.
//
// Semantic conflict detection against a stubbed Ix graph.

import { describe, expect, it } from "vitest";
import { ixNeighbourhood, parseAround, semanticConflicts, shareSlots, type Neighbourhood, type PeerChanges, type Relation } from "../conflicts.js";
import type { IxRunner } from "../ix.js";

/** A stub graph: file → files that depend on it, with how. */
function graph(edges: Record<string, Record<string, Relation[]>>) {
  const asked: string[] = [];
  const fn = async (f: string): Promise<Neighbourhood> => {
    asked.push(f);
    if (f === "boom.ts") throw new Error("backend down");
    return new Map(Object.entries(edges[f] ?? {}).map(([k, v]) => [k, new Set(v)]));
  };
  return { fn, asked };
}

const peer = (address: string, files: string[], repo = "acme/widgets"): PeerChanges => ({ address, own: `u-${address}`, sid: `s-${address}`, ref: "abcdef", repo, files });

describe("semanticConflicts", () => {
  it("flags my change reaching a file a peer edits, and theirs reaching mine", async () => {
    const g = graph({
      "src/auth/token.ts": { "src/api/handler.ts": ["caller", "importer"], "test/t.ts": ["test"] },
      "src/db/pool.ts": { "src/auth/session.ts": ["user"] },
    });
    const r = await semanticConflicts({
      mine: ["src/auth/token.ts", "src/auth/session.ts"],
      peers: [peer("bob@x", ["src/api/handler.ts", "src/db/pool.ts"]), peer("carol@y", ["docs/readme.md"])],
      repo: "Acme/Widgets",
      neighbourhood: g.fn,
    });
    expect(r.errors).toEqual([]);
    expect(r.conflicts.map((c) => [c.peer.address, c.mine, c.theirs, c.direction, c.via])).toEqual([
      ["bob@x", "src/auth/token.ts", "src/api/handler.ts", "mine-affects-theirs", ["caller", "importer"]],
      ["bob@x", "src/auth/session.ts", "src/db/pool.ts", "theirs-affects-mine", ["user"]],
    ]);
    expect(r.conflicts[0].message).toBe("possible semantic conflict with bob@x: your change to src/auth/token.ts affects src/api/handler.ts they're editing (it calls into src/auth/token.ts)");
    expect(r.conflicts[1].message).toBe("possible semantic conflict with bob@x: their change to src/db/pool.ts affects src/auth/session.ts you're editing (it uses src/db/pool.ts)");
  });

  it("leaves same-file overlap to core, skips other repos and unsafe paths, survives lookup errors", async () => {
    const g = graph({ "a.ts": { "b.ts": ["caller"] } });
    const r = await semanticConflicts({
      mine: ["a.ts", "boom.ts", "/abs/x.ts"],
      peers: [peer("bob@x", ["a.ts", "../../etc/passwd"]), peer("dan@z", ["b.ts"], "acme/other")],
      repo: "acme/widgets",
      neighbourhood: g.fn,
    });
    expect(r.conflicts).toEqual([]);
    expect(r.errors).toEqual(["boom.ts: backend down"]);
    expect(g.asked).not.toContain("/abs/x.ts");
    expect(g.asked).not.toContain("../../etc/passwd");
  });

  it("L5: shares the 'theirs' slots fairly between peers", () => {
    const many = Array.from({ length: 80 }, (_, i) => `big${i}.ts`);
    const slots = shareSlots([{ files: many }, { files: ["small1.ts", "small2.ts"] }, { files: ["mine.ts", "/abs.ts", "x.ts"] }], new Set(["mine.ts"]), 50);
    expect(slots).toHaveLength(50);
    expect(slots).toEqual(expect.arrayContaining(["small1.ts", "small2.ts", "x.ts"]));
    expect(slots).not.toContain("mine.ts");
    expect(slots).not.toContain("/abs.ts");
  });

  it("L5: stops at the total time budget and says so", async () => {
    let t = 0;
    const slow = async (f: string): Promise<Neighbourhood> => {
      t += 400; // each lookup "takes" 400 ms of the clock
      return new Map(f === "a.ts" ? [["b.ts", new Set<Relation>(["caller"])]] : []);
    };
    const r = await semanticConflicts({ mine: ["a.ts", "c.ts", "d.ts"], peers: [peer("bob@x", ["b.ts", "e.ts"])], neighbourhood: slow, budgetMs: 1000, now: () => t });
    expect(r.conflicts.map((c) => c.theirs)).toEqual(["b.ts"]);
    expect(r.errors.at(-1)).toMatch(/^time budget \(1 s\) reached: 2 file\(s\) not checked$/);
    // A lookup that hangs is abandoned at the budget.
    const hang = () => new Promise<Neighbourhood>(() => {});
    const h = await semanticConflicts({ mine: ["a.ts"], peers: [peer("bob@x", ["b.ts"])], neighbourhood: hang, budgetMs: 50 });
    expect(h.errors.at(-1)).toMatch(/time budget/);
  });

  it("caps lookups", async () => {
    const g = graph({});
    await semanticConflicts({ mine: Array.from({ length: 40 }, (_, i) => `m${i}.ts`), peers: [peer("p", Array.from({ length: 80 }, (_, i) => `t${i}.ts`))], neighbourhood: g.fn });
    expect(g.asked).toHaveLength(25 + 50);
  });
});

describe("ixNeighbourhood (ix around --format json)", () => {
  it("parses callers, users, tests and importers by path, and caches", async () => {
    const calls: string[][] = [];
    const ix: IxRunner = {
      run: async (argv) => {
        calls.push([...argv]);
        return {
          code: 0,
          stderr: "",
          stdout: JSON.stringify({
            path: argv[1],
            symbols: [{ name: "f", callers: { total: 2, rows: [{ path: "a.ts" }, { path: "/abs/z.ts" }] }, users: { total: 1, rows: [{ path: "b.ts" }] }, tests: { total: 1, rows: [{ path: "t/a.test.ts" }] } }],
            importers: { total: 2, rows: [{ path: "a.ts" }, { path: "./c.ts" }], tests: 0 },
          }),
        };
      },
    };
    const n = ixNeighbourhood(ix);
    const h = await n("src/x.ts");
    await n("src/x.ts");
    expect(calls).toEqual([["around", "src/x.ts", "--format", "json", "--limit", "20"]]);
    expect(Object.fromEntries([...h].map(([k, v]) => [k, [...v]]))).toEqual({ "a.ts": ["caller", "importer"], "b.ts": ["user"], "t/a.test.ts": ["test"], "c.ts": ["importer"] });
    // Never asks about something that could be read as an option.
    expect((await n("-rf")).size).toBe(0);
    expect(calls).toHaveLength(1);
  });

  it("parseAround tolerates junk", () => {
    expect(parseAround(null, "x").size).toBe(0);
    expect(parseAround({ symbols: "no", importers: 3 }, "x").size).toBe(0);
    expect(parseAround({ importers: { rows: [{ path: "x" }] } }, "x").size).toBe(0);
  });
});
