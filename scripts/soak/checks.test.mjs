// Copyright 2026 Ix Infrastructure Inc.
//
// The soak harness's own checks that decide pass or fail without running a soak.
//   node --test scripts/soak/checks.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";
import { deliveryErrors, JOIN_APPROVAL_POLL_MS, joinedHere, POISON_RACE_MS, refusedWhilePairChanged, sameSummary } from "./lib.mjs";

test("a shown status matches the posted one exactly, apart from ls's agent count", () => {
  assert.equal(sameSummary("st-c2-u2-9", "st-c2-u2-9"), true);
  assert.equal(sameSummary("st-c2-u2-9 (+1 agent)", "st-c2-u2-9"), true);
  assert.equal(sameSummary("st-c2-u2-9 (+3 agents)", "st-c2-u2-9"), true);
  // A prefix is another status: startsWith let st-c2-u2-1 pass for st-c2-u2-12.
  assert.equal(sameSummary("st-c2-u2-12", "st-c2-u2-1"), false);
  assert.equal(sameSummary("st-c2-u2-1x", "st-c2-u2-1"), false);
  assert.equal(sameSummary(undefined, "st-c2-u2-1"), false);
});

test("a poison message is excused only for a pair change in its window and a refusal of that sender", () => {
  const t0 = 1_000_000;
  const m = { sentAt: t0 + 100_000, from: { user: "p2p:aaa" }, to: { user: "p2p:bbb" } };
  const pair = new Set(["p2p:aaa", "p2p:bbb"]);
  const refusal = { dev: "u2d1", t: 110_000, line: "rejected an envelope from wss://r/v3: not-friends: p2p:aaa -> p2p:bbb not authorised for p2p:aaa/dm" };
  const changedAt = (t) => [{ t, kind: "friend", users: pair }];
  // The unfriend while in flight, and the refusal: excused.
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: changedAt(m.sentAt + 5000), rejected: [refusal], t0 }), true);
  // No refusal logged for it: not excused (it wasn't given up for another reason).
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: changedAt(m.sentAt + 5000), rejected: [], t0 }), false);
  // A refusal of someone else's envelope, or on another device: not this one.
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: changedAt(m.sentAt + 5000), rejected: [{ ...refusal, line: refusal.line.replace("p2p:aaa ->", "p2p:ccc ->") }], t0 }), false);
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: changedAt(m.sentAt + 5000), rejected: [{ ...refusal, dev: "u2d2" }], t0 }), false);
  // A pair change long after: the window has an end.
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: changedAt(m.sentAt + POISON_RACE_MS + 1), rejected: [{ ...refusal, t: 100_000 + POISON_RACE_MS + 2 }], t0 }), false);
  // Another pair's change: no excuse.
  assert.equal(refusedWhilePairChanged({ m, devId: "u2d1", socialLog: [{ t: m.sentAt + 5000, kind: "friend", users: new Set(["p2p:aaa", "p2p:ccc"]) }], rejected: [refusal], t0 }), false);
});

test("a re-join counts as joined here when an earlier try already joined, and waits long enough for approval", () => {
  assert.equal(joinedHere({ status: "joined" }), true);
  // Seed 3: the first try joined locally while its approval was still on the way; the heal's
  // retry answers `already`, which used to count as a failed re-join.
  assert.equal(joinedHere({ status: "already" }), true);
  assert.equal(joinedHere({ status: "waiting" }), false);
  assert.equal(joinedHere({ status: "unconfirmed" }), false);
  assert.equal(joinedHere(undefined), false);
  assert.ok(JOIN_APPROVAL_POLL_MS >= 30_000);
});

test("an undelivered accept says why, per relay (seed 9)", () => {
  const json = {
    error: "undelivered",
    delivered: {
      relays: [],
      errors: [
        { did: "d_a", relay: "wss://relay-a/v3", code: "undeliverable" },
        { did: "d_b", relay: "wss://relay-a/v3", code: "undeliverable" },
        { did: "d_a", relay: "wss://relay-b/v3", code: "rate-limited" },
        { did: "d_c", relay: "", code: "no-cert" },
      ],
    },
  };
  assert.deepEqual(deliveryErrors(json), ["(none): no-cert", "wss://relay-a/v3: undeliverable", "wss://relay-b/v3: rate-limited"]);
  assert.deepEqual(deliveryErrors({ error: "undelivered" }), []);
  assert.deepEqual(deliveryErrors(undefined), []);
});
