// Copyright 2026 Ix Infrastructure Inc.
//
// Who listens on the local Ix endpoint's port. "Local" is a loopback port, and on a machine other
// people log in to, another user can listen on it while this user's backend is down: they would
// receive what `ix note` / `ix session` send (session labels, repos, branches, statuses, edited
// files, a peer's imported note) and the local token Ix sends to loopback. Ix's backend has no
// identity it can prove (only /v1/health and the opt-in local token, which a listener would just
// accept), so before ext-ix writes there it asks the operating system who owns every socket
// listening on that port on a loopback or wildcard address:
//   - Linux: /proc/net/tcp and /proc/net/tcp6 (state 0A = LISTEN, with the owner's uid);
//   - macOS: `netstat -an` lists every user's listening sockets (without owners), and
//     `lsof -iTCP:<port> -sTCP:LISTEN` lists the ones this user's processes hold (a non-root lsof
//     can't see other users'). Every listener netstat shows must be matched by one of this user's.
// Every such listener must be this user's, or root's (root can read this user's files anyway, and
// Docker's port proxy runs as root on Linux), and there must be at least one. Anything else, or an
// answer that can't be read, or another platform, means "no": graph writes stay off. This narrows
// the window; it can't close it (a listener can appear between the check and the write).

import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";

export type ListenerVerdict = { ok: true } | { ok: false; why: string };
/** Checks the listener of a loopback endpoint (http(s) URL). */
export type ListenerCheck = (endpoint: string) => Promise<ListenerVerdict>;

export interface Listener {
  /** The local address, normalized: an IPv4 dotted quad, or IPv6 in lower-case hex groups. */
  addr: string;
  port: number;
  uid?: number;
  pid?: number;
}

/** The port of an http(s) endpoint, or undefined. */
export function endpointPort(endpoint: string): number | undefined {
  try {
    const u = new URL(endpoint);
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    const p = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    return Number.isInteger(p) && p > 0 && p < 65536 ? p : undefined;
  } catch {
    return undefined;
  }
}

/** Whether a connection to a loopback address could reach a socket bound to `addr`. */
export function reachesLoopback(addr: string): boolean {
  const a = addr.toLowerCase();
  if (a === "*" || a === "0.0.0.0" || a === "::" || a === "0:0:0:0:0:0:0:0" || a === "::1" || a === "0:0:0:0:0:0:0:1") return true;
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(a)) return true;
  const mapped = /^(?:0:0:0:0:0:ffff|::ffff):(.+)$/.exec(a)?.[1];
  if (mapped) return mapped === "0.0.0.0" || /^127\./.test(mapped) || /^7f[0-9a-f]{2}:[0-9a-f]{1,4}$/.test(mapped) || mapped === "0:0";
  return false;
}

/** One /proc/net/tcp{,6} address (hex, little-endian 32-bit words) as text. */
export function procAddr(hex: string): string | undefined {
  if (/^[0-9A-Fa-f]{8}$/.test(hex)) {
    const b = hex.match(/../g)!.map((x) => parseInt(x, 16)).reverse();
    return b.join(".");
  }
  if (/^[0-9A-Fa-f]{32}$/.test(hex)) {
    const bytes: number[] = [];
    for (const w of hex.match(/.{8}/g)!) bytes.push(...w.match(/../g)!.map((x) => parseInt(x, 16)).reverse());
    const groups: string[] = [];
    for (let i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
    // ::ffff:a.b.c.d keeps its IPv4 tail readable.
    if (groups.slice(0, 5).every((g) => g === "0") && groups[5] === "ffff") return `::ffff:${bytes.slice(12).join(".")}`;
    return groups.join(":");
  }
  return undefined;
}

/** LISTEN sockets from /proc/net/tcp or tcp6 text. */
export function parseProcNet(text: string): Listener[] {
  const out: Listener[] = [];
  for (const line of text.split("\n").slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== "0A") continue;
    const [addrHex, portHex] = f[1].split(":");
    const addr = procAddr(addrHex ?? "");
    const port = parseInt(portHex ?? "", 16);
    const uid = Number(f[7]);
    if (addr === undefined || !Number.isInteger(port) || !Number.isInteger(uid)) continue;
    out.push({ addr, port, uid });
  }
  return out;
}

/** An address as netstat (`127.0.0.1`, `::1`, `*`) or lsof (`[::1]`, `*`) prints it, normalized. */
function normAddr(a: string): string {
  const x = a.replace(/^\[|\]$/g, "").replace(/%.*$/, "").toLowerCase();
  return x === "*" || x === "0.0.0.0" || x === "::" ? "*" : x;
}

/** LISTEN sockets from macOS `netstat -an` (no owners). Undefined when the output isn't that. */
export function parseNetstat(text: string): Listener[] | undefined {
  const lines = text.split("\n");
  if (!lines.some((l) => /^Proto\s+Recv-Q\s+Send-Q\s+Local Address/.test(l))) return undefined;
  const out: Listener[] = [];
  for (const line of lines) {
    if (!/^tcp[46]{1,2}\s/.test(line) || !/\sLISTEN\s*$/.test(line)) continue;
    const local = line.trim().split(/\s+/)[3] ?? "";
    const dot = local.lastIndexOf(".");
    const port = Number(local.slice(dot + 1));
    if (dot < 0 || !Number.isInteger(port)) return undefined;
    out.push({ addr: normAddr(local.slice(0, dot)), port });
  }
  return out;
}

/** This user's LISTEN sockets from `lsof -nP -iTCP:<port> -sTCP:LISTEN -Fpun` (a `p`, `u`, then `n` per socket). */
export function parseLsof(text: string): Listener[] {
  const out: Listener[] = [];
  let pid: number | undefined;
  let uid: number | undefined;
  for (const line of text.split("\n")) {
    const k = line[0];
    const v = line.slice(1);
    if (k === "p") {
      pid = Number(v);
      uid = undefined;
    } else if (k === "u") uid = Number(v);
    else if (k === "n") {
      const colon = v.lastIndexOf(":");
      const port = Number(v.slice(colon + 1));
      if (colon < 0 || !Number.isInteger(port)) continue;
      out.push({ addr: normAddr(v.slice(0, colon)), port, ...(Number.isInteger(pid) ? { pid } : {}), ...(Number.isInteger(uid) ? { uid } : {}) });
    }
  }
  return out;
}

/**
 * macOS: every listener on `port` that netstat shows (all users) must be matched, address for
 * address, by one this user's (or root's) lsof shows; one left over belongs to someone lsof can't see.
 */
export function judgeDarwin(all: readonly Listener[], mine: readonly Listener[], port: number, uid: number): ListenerVerdict {
  const want = all.filter((l) => l.port === port && reachesLoopback(l.addr));
  if (want.length === 0) return { ok: false, why: `nothing listens on port ${port} (is the Ix backend running?)` };
  const have = mine.filter((l) => l.port === port && (l.uid === uid || l.uid === 0));
  const left = new Map<string, number>();
  for (const l of have) left.set(l.addr, (left.get(l.addr) ?? 0) + 1);
  for (const l of want) {
    const n = left.get(l.addr) ?? 0;
    if (n === 0) return { ok: false, why: `port ${port} (${l.addr}) is held by a process that isn't yours, not your Ix backend` };
    left.set(l.addr, n - 1);
  }
  return { ok: true };
}

/** The verdict for the listeners on `port`: all owned by `uid` (or root), and at least one. */
export function judgeListeners(listeners: readonly Listener[], port: number, uid: number): ListenerVerdict {
  const mine = listeners.filter((l) => l.port === port && reachesLoopback(l.addr));
  if (mine.length === 0) return { ok: false, why: `nothing listens on port ${port} (is the Ix backend running?)` };
  for (const l of mine) {
    if (typeof l.uid !== "number") return { ok: false, why: `couldn't tell who listens on port ${port}` };
    if (l.uid !== uid && l.uid !== 0) return { ok: false, why: `port ${port} is held by another user (uid ${l.uid}), not your Ix backend` };
  }
  return { ok: true };
}

const run = (cmd: string, args: string[]): Promise<string> =>
  new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 10_000, maxBuffer: 8 * 1024 * 1024, env: { PATH: "/usr/sbin:/usr/bin:/bin:/sbin", LANG: "C" }, windowsHide: true }, (err, stdout) => (err ? reject(err) : resolve(String(stdout))));
  });

export interface ListenerDeps {
  platform?: NodeJS.Platform;
  uid?: number;
  readFile?: (path: string) => Promise<string>;
  exec?: (cmd: string, args: string[]) => Promise<string>;
}

/** The real check (see the top of this file). */
export async function checkLoopbackListener(endpoint: string, d: ListenerDeps = {}): Promise<ListenerVerdict> {
  const port = endpointPort(endpoint);
  if (port === undefined) return { ok: false, why: "the local endpoint has no port" };
  const platform = d.platform ?? process.platform;
  const uid = d.uid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  if (uid === undefined) return { ok: false, why: "this platform can't tell who listens on a port" };
  const read = d.readFile ?? ((p: string) => readFile(p, "utf8"));
  const exec = d.exec ?? run;
  try {
    if (platform === "linux") {
      const texts = await Promise.all(["/proc/net/tcp", "/proc/net/tcp6"].map((p) => read(p).catch(() => "")));
      if (texts.every((t) => t === "")) return { ok: false, why: "couldn't read /proc/net/tcp" };
      return judgeListeners(texts.flatMap(parseProcNet), port, uid);
    }
    if (platform === "darwin") {
      const all = parseNetstat(await exec("/usr/sbin/netstat", ["-an"]));
      if (!all) return { ok: false, why: "couldn't read netstat's sockets" };
      // lsof exits 1 when it finds nothing: no socket of this user's.
      const mine = parseLsof(await exec("/usr/sbin/lsof", ["-nP", "-a", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fpun"]).catch(() => ""));
      return judgeDarwin(all, mine, port, uid);
    }
  } catch {
    return { ok: false, why: `couldn't tell who listens on port ${port}` };
  }
  return { ok: false, why: `can't tell who listens on a port on ${platform}` };
}
