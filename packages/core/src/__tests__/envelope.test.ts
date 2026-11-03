// Copyright 2026 Ix Infrastructure Inc.
import { describe, expect, it } from "vitest";
import { FakeKartr, NOW_MS } from "./fixtures.js";
import {
  decodeEnvelope,
  envelopeAad,
  openEnvelope,
  parsePlaintext,
  sealEnvelope,
  verifyEnvelopeSignature,
  type EnvelopeHeader,
} from "../envelope.js";
import { fromUtf8 } from "../encoding.js";
import {
  advanceWindow,
  checkReplay,
  checkSeq,
  mergeReplay,
  mergeWindows,
  recordReplay,
  NONCE_LRU_SIZE,
  REPLAY_MAX_AGE_MS,
  REPLAY_WINDOW,
  type SeqWindow,
} from "../replay.js";

const kartr = new FakeKartr();
const alice = kartr.device("alice@a.example");
const bob = kartr.device("bob@b.example");

const header = (): EnvelopeHeader => ({
  from: alice.userId,
  fdid: alice.deviceId,
  fcert: alice.cert,
  to: bob.userId,
  tdid: bob.deviceId,
  own: alice.userId,
  sid: "sess-1",
  seq: 7,
  ts: NOW_MS,
  kind: "msg",
});

function seal(plaintext: { text: string; sender: object } = { text: "hi", sender: {} }) {
  return sealEnvelope({ ...header(), plaintext, sender: alice, recipientKpk: bob.agreementPublicKey });
}

describe("envelope seal/open", () => {
  it("round-trips", () => {
    const jws = seal();
    const d = verifyEnvelopeSignature(jws, alice.signingPublicKey);
    expect(d.header).toEqual({ alg: "EdDSA", typ: "p2p-msg+jws", kid: alice.deviceId });
    expect(Object.keys(d.payload)).toEqual(["v", "from", "fdid", "fcert", "to", "tdid", "own", "sid", "seq", "ts", "n", "epk", "ct", "kind"]);
    const pt = parsePlaintext(openEnvelope(d.payload, bob.agreementSecretKey, alice.agreementPublicKey));
    expect(pt).toEqual({ text: "hi", sender: {} });
    expect(d.payload.fcert).toBe(alice.cert);
    expect(d.payload.own).toBe(alice.userId);
  });

  it("uses the fixed-string AAD", () => {
    expect(fromUtf8(envelopeAad(header()))).toBe(
      `p2p/v1|alice@a.example|${alice.deviceId}|bob@b.example|${bob.deviceId}|alice@a.example|sess-1|7|${NOW_MS}|msg`,
    );
  });

  it("fresh ephemeral key and nonce per seal", () => {
    const a = decodeEnvelope(seal()).payload;
    const b = decodeEnvelope(seal()).payload;
    expect(a.epk).not.toBe(b.epk);
    expect(a.n).not.toBe(b.n);
  });

  it("only the addressed device can open", () => {
    const carol = kartr.device("carol@c.example");
    const p = decodeEnvelope(seal()).payload;
    expect(() => openEnvelope(p, carol.agreementSecretKey, alice.agreementPublicKey)).toThrow(/decrypt-failed/);
  });

  it("binds the static sender key", () => {
    const mallory = kartr.device("mallory@m.example");
    const p = decodeEnvelope(seal()).payload;
    expect(() => openEnvelope(p, bob.agreementSecretKey, mallory.agreementPublicKey)).toThrow(/decrypt-failed/);
  });

  it("a header field changed under the AAD fails to open", () => {
    const p = decodeEnvelope(seal()).payload;
    for (const tweak of [{ seq: 8 }, { ts: NOW_MS + 1 }, { kind: "idle" as const }, { sid: "sess-2" }, { own: "bob@b.example" }]) {
      expect(() => openEnvelope({ ...p, ...tweak }, bob.agreementSecretKey, alice.agreementPublicKey)).toThrow(
        /decrypt-failed/,
      );
    }
  });

  it("rejects malformed payloads", () => {
    expect(() =>
      sealEnvelope({ ...header(), sid: "a|b", plaintext: { text: "", sender: {} }, sender: alice, recipientKpk: bob.agreementPublicKey }),
    ).toThrow(/must not contain/);
    expect(() =>
      sealEnvelope({ ...header(), own: "x|y", plaintext: { text: "", sender: {} }, sender: alice, recipientKpk: bob.agreementPublicKey }),
    ).toThrow(/must not contain/);
    expect(() => parsePlaintext(new TextEncoder().encode('{"text":"x"}'))).toThrow(/sender must be an object/);
  });
});

describe("replay window", () => {
  const f = { own: "o@x", sid: "s", seq: 10, ts: NOW_MS, n: "n1" };
  it("accepts fresh, rejects stale ts, repeated nonce, old seq", () => {
    expect(checkReplay(f, undefined, NOW_MS)).toBeUndefined();
    // D6: up to 10 min of future skew, up to 24h10m late.
    expect(checkReplay(f, undefined, NOW_MS - 10 * 60_000)).toBeUndefined();
    expect(checkReplay(f, undefined, NOW_MS - 10 * 60_000 - 1)?.reason).toBe("stale-timestamp");
    expect(checkReplay(f, undefined, NOW_MS + 2 * 3600_000)).toBeUndefined();
    expect(checkReplay(f, undefined, NOW_MS + REPLAY_MAX_AGE_MS)).toBeUndefined();
    expect(checkReplay(f, undefined, NOW_MS + REPLAY_MAX_AGE_MS + 1)?.reason).toBe("stale-timestamp");
    const rec = recordReplay(f, undefined);
    expect(checkReplay(f, rec, NOW_MS)?.reason).toBe("replayed-seq"); // the window is checked first
    expect(checkReplay({ ...f, seq: 11 }, rec, NOW_MS)?.reason).toBe("replayed-nonce"); // backup
    expect(checkReplay({ ...f, n: "n2" }, rec, NOW_MS)?.reason).toBe("replayed-seq");
    expect(checkReplay({ ...f, n: "n2", seq: 9 }, rec, NOW_MS)).toBeUndefined(); // reordered, within the window
    expect(checkReplay({ ...f, n: "n2", seq: 11 }, rec, NOW_MS)).toBeUndefined();
    expect(checkReplay({ ...f, n: "n2", seq: 3, sid: "other" }, rec, NOW_MS)).toBeUndefined();
    // Same sid, different owner: a different session.
    expect(checkReplay({ ...f, n: "n2", seq: 3, own: "p@y" }, rec, NOW_MS)).toBeUndefined();
  });

  it("sliding window: reordering is fine, each seq once, too-old rejected (D7)", () => {
    const at = (seq: number, n = `n${seq}`) => ({ ...f, seq, n });
    let rec = recordReplay(at(8), undefined);
    // Out of order: 7 after 8 is accepted, once.
    expect(checkReplay(at(7), rec, NOW_MS)).toBeUndefined();
    rec = recordReplay(at(7), rec);
    expect(checkReplay(at(7, "fresh"), rec, NOW_MS)?.reason).toBe("replayed-seq");
    expect(checkReplay(at(8, "fresh"), rec, NOW_MS)?.reason).toBe("replayed-seq");
    // Jump far ahead; seqs within W behind H are still open, older ones are not.
    rec = recordReplay(at(8 + REPLAY_WINDOW), rec);
    expect(checkReplay(at(9), rec, NOW_MS)).toBeUndefined(); // H - 511
    expect(checkReplay(at(8, "fresh"), rec, NOW_MS)?.reason).toBe("seq-too-old"); // H - 512
    expect(checkReplay(at(0, "fresh"), rec, NOW_MS)?.reason).toBe("seq-too-old");
    // No restart reset (L1): a sender starting over at 0 is too old.
    rec = recordReplay(at(5000), rec);
    expect(checkReplay(at(0, "x"), rec, NOW_MS)?.reason).toBe("seq-too-old");
  });

  it("window bookkeeping matches a reference set", () => {
    // Random arrival order over seqs 1..1500 with duplicates.
    let w: SeqWindow | undefined;
    const accepted = new Set<number>();
    let h = -Infinity;
    let x = 12345;
    const rnd = () => (x = (x * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    for (let i = 0; i < 4000; i++) {
      const seq = 1 + Math.floor(rnd() * 1500);
      const expected = seq > h ? undefined : h - seq >= REPLAY_WINDOW ? "seq-too-old" : accepted.has(seq) ? "replayed-seq" : undefined;
      expect(checkSeq(seq, w)?.reason).toBe(expected);
      if (!expected) {
        w = advanceWindow(seq, w);
        accepted.add(seq);
        h = Math.max(h, seq);
      }
    }
  });

  it("merging windows ORs them after aligning to the larger H", () => {
    const a = advanceWindow(5, advanceWindow(3, undefined)); // h 5: {3, 5}
    const b = advanceWindow(700, advanceWindow(200, advanceWindow(4, undefined))); // h 700: {200, 700} (4 dropped)
    const m = mergeWindows(a, b)!;
    expect(m.h).toBe(700);
    expect(checkSeq(200, m)?.reason).toBe("replayed-seq");
    expect(checkSeq(201, m)).toBeUndefined();
    expect(checkSeq(5, m)?.reason).toBe("seq-too-old");
    // Commutative and idempotent.
    expect(mergeWindows(b, a)).toEqual(m);
    expect(mergeWindows(m, m)).toEqual(m);
    const c = advanceWindow(6, advanceWindow(1, undefined));
    const ac = mergeWindows(a, c)!;
    expect(ac.h).toBe(6);
    for (const seq of [1, 3, 5, 6]) expect(checkSeq(seq, ac)?.reason).toBe("replayed-seq");
    expect(checkSeq(2, ac)).toBeUndefined();
    expect(checkSeq(4, ac)).toBeUndefined();
    expect(mergeReplay({ nonces: ["p"], windows: { k: a } }, { nonces: ["q"], windows: { k: c } }).windows.k).toEqual(ac);
  });

  it("keeps an LRU of the last 10k nonces", () => {
    let rec = recordReplay({ ...f, n: "first" }, undefined);
    rec = { ...rec, nonces: [...rec.nonces, ...Array.from({ length: NONCE_LRU_SIZE - 1 }, (_, i) => `n${i}`)] };
    expect(checkReplay({ ...f, seq: 99, n: "first" }, rec, NOW_MS)?.reason).toBe("replayed-nonce");
    rec = recordReplay({ ...f, seq: 11, n: "last" }, rec);
    expect(rec.nonces).toHaveLength(NONCE_LRU_SIZE);
    expect(checkReplay({ ...f, seq: 99, n: "first" }, rec, NOW_MS)).toBeUndefined();
  });
});
