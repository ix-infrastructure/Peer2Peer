// Copyright 2026 Ix Infrastructure Inc.
//
// Ix is optional and the person's to install: when `p2p extensions` says Ix isn't installed and the
// person hasn't said no, the model hears once per session that it may suggest Ix and must never
// install it itself. Declined, installed, or an older CLI without the field: nothing is said.

import { describe, expect, it } from "vitest";
import { ixAgentHint, parseIxAdvice } from "../lib.js";
import { makeBridge, tick, World } from "./world.js";

const INSTALL = "curl -fsSL https://ix-infra.com/install.sh | sh";
const advice = (over: Record<string, unknown> = {}) => ({ installed: false, declined: false, recommended: true, install: INSTALL, ...over });
type Out = { hookSpecificOutput?: { additionalContext?: string } };
const ctx = (o: unknown) => (o as Out).hookSpecificOutput?.additionalContext ?? "";

async function bridgeWith(ix: unknown) {
  const world = new World();
  world.ix = ix;
  const made = await makeBridge({ world });
  for (let i = 0; i < 5; i++) await tick();
  return made;
}

describe("the Ix hint", () => {
  it("pure: only when recommended; malformed output gives none; the command is made inert", () => {
    expect(ixAgentHint(parseIxAdvice(advice()))).toContain("Never install it yourself");
    expect(ixAgentHint(parseIxAdvice(advice({ declined: true, recommended: false })))).toBeUndefined();
    expect(ixAgentHint(parseIxAdvice(advice({ installed: true, recommended: false })))).toBeUndefined();
    expect(parseIxAdvice({ installed: "no" })).toBeUndefined();
    expect(ixAgentHint(parseIxAdvice(advice({ install: "a <b> c" })))).not.toContain("<b>");
  });

  it("not installed, not declined: said once, at SessionStart, never again", async () => {
    const { bridge, world } = await bridgeWith(advice());
    expect(world.calls.some((c) => c.argv[0] === "extensions")).toBe(true);
    const first = ctx(await bridge.onHook({ event: "SessionStart", sessionId: "thread-1" }));
    expect(first).toContain("Ix isn't installed");
    const second = ctx(await bridge.onHook({ event: "UserPromptSubmit" }));
    const third = ctx(await bridge.onHook({ event: "UserPromptSubmit" }));
    const all = [first, second, third];
    expect(all.filter((t) => t.includes("Ix isn't installed"))).toHaveLength(1);
    const hint = all.find((t) => t.includes("Ix isn't installed")) ?? "";
    expect(hint).toContain("optional");
    expect(hint).toContain("suggest it to your user once");
    expect(hint).toContain("Never install it yourself");
    expect(hint).toContain(INSTALL);
    await bridge.close();
  });

  it("only at SessionStart: a UserPromptSubmit (a queued or forged turn raises one too) never carries it", async () => {
    const { bridge } = await bridgeWith(advice());
    const prompts = [ctx(await bridge.onHook({ event: "UserPromptSubmit" })), ctx(await bridge.onHook({ event: "UserPromptSubmit" }))];
    expect(prompts.join("\n")).not.toContain("Ix isn't installed");
    expect(ctx(await bridge.onHook({ event: "SessionStart", sessionId: "thread-1" }))).toContain("Ix isn't installed");
    await bridge.close();
  });

  for (const [name, ix] of [
    ["declined", advice({ declined: true, recommended: false })],
    ["installed", advice({ installed: true, recommended: false })],
    ["an older CLI without the field", undefined],
  ] as const) {
    it(`${name}: no hint`, async () => {
      const { bridge } = await bridgeWith(ix);
      const texts = [ctx(await bridge.onHook({ event: "SessionStart", sessionId: "thread-1" })), ctx(await bridge.onHook({ event: "UserPromptSubmit" }))];
      expect(texts.join("\n")).not.toContain("Ix isn't installed");
      await bridge.close();
    });
  }
});
