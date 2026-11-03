// Copyright 2026 Ix Infrastructure Inc.
//
// Kartr signing keys: the JWKS document, the key-id derivation and a cache
// that honours the spec's 1h TTL and refetches on an unknown kid.

import { b64uDecode, b64uEncode, utf8 } from "./encoding.js";
import { sha256 } from "./crypto.js";
import { fail } from "./errors.js";

export interface Jwk {
  kty: "OKP";
  crv: "Ed25519";
  kid: string;
  x: string;
  use?: "sig";
}

export interface JwksDocument {
  keys: Jwk[];
}

/** Resolves a Kartr `kid` to its Ed25519 public key. */
export interface KartrKeys {
  resolve(kid: string): Promise<Uint8Array | undefined>;
}

/** `b64u(sha256(name))[:16]`, where name is the KMS key-version resource name. */
export function kartrKeyId(keyVersionName: string): string {
  return b64uEncode(sha256(utf8(keyVersionName))).slice(0, 16);
}

/**
 * Parses a JWKS document into kid -> public key. Keys that are not
 * OKP/Ed25519 signing keys are skipped (a future JWKS may carry others); a
 * malformed Ed25519 key or a duplicate kid is an error.
 */
export function parseJwks(doc: unknown): Map<string, Uint8Array> {
  if (typeof doc !== "object" || doc === null || !Array.isArray((doc as JwksDocument).keys)) {
    fail("malformed", "JWKS must be an object with a keys array");
  }
  const out = new Map<string, Uint8Array>();
  for (const k of (doc as { keys: unknown[] }).keys) {
    if (typeof k !== "object" || k === null) continue;
    const j = k as Record<string, unknown>;
    if (j.kty !== "OKP" || j.crv !== "Ed25519") continue;
    if (j.use !== undefined && j.use !== "sig") continue;
    if (typeof j.kid !== "string" || j.kid === "" || typeof j.x !== "string") fail("malformed", "JWK missing kid/x");
    if (out.has(j.kid)) fail("malformed", `duplicate kid ${j.kid}`);
    out.set(j.kid, b64uDecode(j.x, 32));
  }
  return out;
}

export function jwkFromPublicKey(kid: string, publicKey: Uint8Array): Jwk {
  return { kty: "OKP", crv: "Ed25519", kid, x: b64uEncode(publicKey), use: "sig" };
}

/** A fixed key set (tests, or a pinned JWKS). */
export function staticKartrKeys(doc: unknown): KartrKeys {
  const keys = parseJwks(doc);
  return { resolve: async (kid) => keys.get(kid) };
}

export interface JwksCacheStore {
  getJwks(): Promise<{ fetchedAt: number; jwks: unknown } | undefined>;
  putJwks(entry: { fetchedAt: number; jwks: unknown }): Promise<void>;
}

export interface JwksCacheOptions {
  /** Fetches `GET /.well-known/p2p-jwks.json` and returns the parsed body. */
  fetchJwks: () => Promise<unknown>;
  /** Optional persistence (a TrustStore satisfies this). */
  store?: JwksCacheStore;
  ttlMs?: number;
  /** Minimum gap between unknown-kid refetches, so a forged kid can't hammer Kartr. */
  minRefetchMs?: number;
  now?: () => number;
}

/** Caches the JWKS for 1h; refetches on an unknown kid (rate-limited). */
export class JwksCache implements KartrKeys {
  private keys?: Map<string, Uint8Array>;
  private fetchedAt = -Infinity;
  private lastAttempt = -Infinity;
  private inflight?: Promise<void>;
  private readonly ttlMs: number;
  private readonly minRefetchMs: number;
  private readonly now: () => number;

  constructor(private readonly opts: JwksCacheOptions) {
    this.ttlMs = opts.ttlMs ?? 3_600_000;
    this.minRefetchMs = opts.minRefetchMs ?? 30_000;
    this.now = opts.now ?? Date.now;
  }

  async resolve(kid: string): Promise<Uint8Array | undefined> {
    if (!this.keys && this.opts.store) {
      const cached = await this.opts.store.getJwks();
      if (cached) {
        try {
          this.keys = parseJwks(cached.jwks);
          this.fetchedAt = cached.fetchedAt;
        } catch {}
      }
    }
    const fresh = this.now() - this.fetchedAt < this.ttlMs;
    if (this.keys && fresh && this.keys.has(kid)) return this.keys.get(kid);
    if (!this.keys || !fresh || this.now() - this.lastAttempt >= this.minRefetchMs) {
      try {
        await this.refresh();
      } catch {
        // Kartr unreachable: keep verifying with the keys we already hold, so
        // existing certificates work offline until they expire.
      }
    }
    return this.keys?.get(kid);
  }

  async refresh(): Promise<void> {
    if (!this.inflight) {
      this.lastAttempt = this.now();
      this.inflight = (async () => {
        const jwks = await this.opts.fetchJwks();
        const keys = parseJwks(jwks);
        this.keys = keys;
        this.fetchedAt = this.now();
        await this.opts.store?.putJwks({ fetchedAt: this.fetchedAt, jwks });
      })().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }
}
