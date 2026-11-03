// Copyright 2026 Ix Infrastructure Inc.
//
// Client addresses for per-IP limits.
//
// An IPv6 user typically controls a whole /64 (often far more), so per-IP
// limits key IPv6 addresses by their /64 prefix; otherwise one host could
// rotate through 2^64 addresses and defeat every limit. IPv4-mapped IPv6
// addresses (::ffff:a.b.c.d) are treated as the IPv4 address.

import { isIPv4, isIPv6 } from "node:net";

/** Expands an IPv6 address to 8 hextets (no zone id), or undefined. */
function expandIPv6(ip: string): string[] | undefined {
  const addr = ip.split("%")[0];
  if (!isIPv6(addr)) return undefined;
  let head: string[];
  let tail: string[];
  if (addr.includes("::")) {
    const [h, t] = addr.split("::");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = addr.split(":");
    tail = [];
  }
  // An embedded IPv4 tail (a.b.c.d) counts as two hextets.
  const last = tail.length > 0 ? tail[tail.length - 1] : head[head.length - 1];
  if (last && isIPv4(last)) {
    const o = last.split(".").map(Number);
    const hex = [((o[0] << 8) | o[1]).toString(16), ((o[2] << 8) | o[3]).toString(16)];
    if (tail.length > 0) tail.splice(tail.length - 1, 1, ...hex);
    else head.splice(head.length - 1, 1, ...hex);
  }
  const fill = 8 - head.length - tail.length;
  if (fill < 0) return undefined;
  return [...head, ...Array<string>(fill).fill("0"), ...tail].map((h) => h.toLowerCase().replace(/^0+(?=.)/, ""));
}

/**
 * Strips what proxies and sockets wrap around an address: brackets
 * (`[2001:db8::1]`), a port (`203.0.113.5:4433`, `[2001:db8::1]:443`).
 */
export function bareAddress(raw: string): string {
  const v = raw.trim();
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(v);
  if (bracketed) return bracketed[1];
  const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(v);
  if (v4port) return v4port[1];
  return v;
}

/**
 * The key per-IP limits use: the IPv4 address itself, or `<first 4 hextets>::/64`
 * for IPv6, after stripping brackets and ports. Anything unparseable is
 * returned unchanged.
 */
export function ipBucket(raw: string): string {
  const ip = bareAddress(raw);
  if (isIPv4(ip)) return ip;
  const h = expandIPv6(ip);
  if (!h) return ip;
  // ::ffff:a.b.c.d
  if (h.slice(0, 5).every((x) => x === "0") && h[5] === "ffff") {
    const a = parseInt(h[6], 16);
    const b = parseInt(h[7], 16);
    return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`;
  }
  return `${h.slice(0, 4).join(":")}::/64`;
}

/**
 * A coarser bucket for budgets one network shouldn't exhaust on its own (P4
 * invite bytes): an IPv6 /64 bucket widens to its /48 (what one site is
 * typically assigned); IPv4 stays the address.
 */
export function ipBucket48(bucket: string): string {
  const m = /^([0-9a-f]+:[0-9a-f]+:[0-9a-f]+):[0-9a-f]+::\/64$/.exec(bucket);
  return m ? `${m[1]}::/48` : bucket;
}

/**
 * The client address of a request. With `trustProxy = n > 0`, the relay sits
 * behind n proxies it runs, each appending to X-Forwarded-For, so the client
 * is the n-th entry from the right. With 0 (the default) the header is ignored.
 */
export function clientAddress(
  remote: string | undefined,
  xff: string | string[] | undefined,
  trustProxy: number,
  onShortHeader?: (hops: number) => void,
): string {
  if (trustProxy > 0) {
    const hops = (Array.isArray(xff) ? xff.join(",") : (xff ?? ""))
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (hops.length >= trustProxy) return bareAddress(hops[hops.length - trustProxy]);
    // Fewer hops than trusted proxies: the header isn't what the operator
    // said it would be (a header-replacing proxy, or a request that bypassed
    // one), so trust only the socket, and say so.
    onShortHeader?.(hops.length);
  }
  return bareAddress(remote ?? "unknown");
}
