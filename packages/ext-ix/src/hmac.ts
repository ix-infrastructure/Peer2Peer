// Copyright 2026 Ix Infrastructure Inc.
//
// Hashed names for x:ix.footprint (SPEC.md §8.6): by default a footprint
// names files, symbols and regions by keyed hashes instead of by name
// (readable names are the person's opt-in, per circle). The key comes from the
// repository itself (its normalized remote and its root commit), so only
// people who have the repository can compute it, and two checkouts of the
// same repository agree on it with no exchange.
//
// What this hides and what it doesn't is spelled out in SPEC.md §8.6: it is
// a speed bump against casual reading by people without the code, not
// encryption. Anyone with the repository (and, for a public one, anyone at
// all) can hash every path and symbol and read a footprint back.

import { createHash, createHmac } from "node:crypto";

export const HMAC_TOKEN_RE = /^h:[A-Za-z0-9_-]{22}$/;
export const KEY_ID_RE = /^k:[0-9a-f]{8}$/;

export interface NameKey {
  /** 32 bytes: sha256("p2p/ix-footprint/v1|" + remote + "|" + rootCommit). */
  key: Buffer;
  /** "k:" + the first 8 hex of sha256(key): lets a receiver tell it holds the same key. */
  keyId: string;
}

/** The repository's key. `rootCommit` is the lexicographically smallest parentless commit. */
export function deriveNameKey(remote: string, rootCommit: string): NameKey {
  const key = createHash("sha256").update(`p2p/ix-footprint/v1|${remote}|${rootCommit}`, "utf8").digest();
  return { key, keyId: `k:${createHash("sha256").update(key).digest("hex").slice(0, 8)}` };
}

/** Picks the root commit from `git rev-list --max-parents=0 HEAD` output (several when histories were merged). */
export function pickRootCommit(revList: string): string | undefined {
  const ids = revList
    .split(/\s+/)
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/.test(s))
    .sort();
  return ids[0];
}

function token(k: NameKey, msg: string): string {
  return `h:${createHmac("sha256", k.key).update(msg, "utf8").digest("base64url").slice(0, 22)}`;
}

/** A file: "f|" + lower(relPath). Case-folded, as Ix compares paths. */
export const hashFile = (k: NameKey, relPath: string): string => token(k, `f|${relPath.toLowerCase()}`);

/** A symbol key `path#qualifiedKey`: "s|" + lower(path) + "#" + qualifiedKey. */
export function hashSymbol(k: NameKey, key: string): string {
  const i = key.indexOf("#");
  return token(k, `s|${key.slice(0, i).toLowerCase()}#${key.slice(i + 1)}`);
}

/** A region (component) name: "c|" + name. */
export const hashRegion = (k: NameKey, name: string): string => token(k, `c|${name}`);
