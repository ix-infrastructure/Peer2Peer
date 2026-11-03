// Copyright 2026 Ix Infrastructure Inc.
//
// §4.3 "Extension state kinds" (cap xstate.v1): the plaintext's `state: {ttl}`
// marker, strictly parsed, and the `<kind>.v<n>` cap of an extension kind.

import { describe, expect, it } from "vitest";
import { EXT_STATE_TTL_MAX, EXT_STATE_TTL_MIN, extensionKindCap, isExtStateTtl, parsePlaintextV3 } from "../index.js";

const pt = (o: Record<string, unknown>) => new TextEncoder().encode(JSON.stringify({ ext: { v: 1, body: { a: 1 } }, fallback: "f", ...o }));

describe("extension state kinds", () => {
  it("an extension kind's plaintext may carry state:{ttl}, and nothing else in it", () => {
    expect(parsePlaintextV3("x:ix.footprint", pt({ state: { ttl: 600 } }))).toEqual({ kind: "x:ix.footprint", ext: { v: 1, body: { a: 1 } }, fallback: "f", state: { ttl: 600 } });
    expect(parsePlaintextV3("x:ix.note", pt({}))).not.toHaveProperty("state");
    for (const bad of [null, [], "600", { ttl: EXT_STATE_TTL_MIN - 1 }, { ttl: EXT_STATE_TTL_MAX + 1 }, { ttl: 60.5 }, { ttl: 60, extra: true, crit: ["extra"] }, {}]) {
      expect(() => parsePlaintextV3("x:ix.footprint", pt({ state: bad }))).toThrow(/state/);
    }
    // Around it, an unknown field is ignored, and refused when critical.
    expect(parsePlaintextV3("x:ix.footprint", pt({ state: { ttl: 60 }, other: 1 }))).not.toHaveProperty("other");
    expect(() => parsePlaintextV3("x:ix.footprint", pt({ state: { ttl: 60 }, other: 1, crit: ["other"] }))).toThrow(/critical/);
  });

  it("ttl bounds and the kind's cap", () => {
    expect([EXT_STATE_TTL_MIN, 600, EXT_STATE_TTL_MAX].every(isExtStateTtl)).toBe(true);
    expect(extensionKindCap("x:ix.footprint")).toBe("x:ix.footprint.v1");
    expect(extensionKindCap("x:ix.footprint", 2)).toBe("x:ix.footprint.v2");
    expect(extensionKindCap("status")).toBeUndefined();
    expect(extensionKindCap(`x:kartr.${"a".repeat(32)}`)).toBeUndefined(); // over 40 characters
  });
});
