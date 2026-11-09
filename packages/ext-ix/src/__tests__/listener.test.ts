// Copyright 2026 Ix Infrastructure Inc.
//
// Who listens on the local Ix endpoint's port (listener.ts, review M1), adversarially: another
// user's listener on a loopback or wildcard address is refused, on Linux (/proc/net/tcp{,6}) and on
// macOS (netstat, matched against this user's lsof); root's (Docker's proxy) is allowed; one on a
// LAN address doesn't count; nothing listening, an unreadable answer or another platform is "no".

import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { checkLoopbackListener, endpointPort, judgeDarwin, judgeListeners, parseLsof, parseNetstat, parseProcNet, procAddr, reachesLoopback } from "../listener.js";

const HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
const row = (local: string, st: string, uid: number) => `   0: ${local} 00000000:0000 ${st} 00000000:00000000 00:00000000 00000000  ${uid}        0 12345 1 0000000000000000 100 0 0 10 0\n`;
const ME = 1000;

describe("reading /proc/net/tcp{,6}", () => {
  it("addresses and ports", () => {
    expect(procAddr("0100007F")).toBe("127.0.0.1");
    expect(procAddr("00000000")).toBe("0.0.0.0");
    expect(procAddr("00000000000000000000000001000000")).toBe("0:0:0:0:0:0:0:1");
    expect(procAddr("00000000000000000000000000000000")).toBe("0:0:0:0:0:0:0:0");
    expect(procAddr("0000000000000000FFFF00000100007F")).toBe("::ffff:127.0.0.1");
    expect(procAddr("zz")).toBeUndefined();
    const ls = parseProcNet(HEAD + row("0100007F:1F9A", "0A", ME) + row("0100007F:1F9A", "01", 7) + row("0101A8C0:1F9A", "0A", 7));
    expect(ls).toEqual([
      { addr: "127.0.0.1", port: 8090, uid: ME },
      { addr: "192.168.1.1", port: 8090, uid: 7 },
    ]);
  });

  it("verdicts: only this user's or root's listeners on loopback or wildcard addresses", () => {
    const j = (rows: string) => judgeListeners(parseProcNet(HEAD + rows), 8090, ME);
    expect(j(row("0100007F:1F9A", "0A", ME))).toEqual({ ok: true });
    expect(j(row("00000000:1F9A", "0A", 0))).toEqual({ ok: true }); // docker-proxy as root
    // Another user, on loopback, the wildcard, ::1, ::, or a v4-mapped loopback: refused.
    for (const local of ["0100007F:1F9A", "0101007F:1F9A", "00000000:1F9A", "00000000000000000000000001000000:1F9A", "00000000000000000000000000000000:1F9A", "0000000000000000FFFF00000100007F:1F9A"]) {
      expect(j(row("0100007F:1F9A", "0A", ME) + row(local, "0A", 1001)), local).toMatchObject({ ok: false, why: expect.stringMatching(/another user \(uid 1001\)/) });
    }
    // Another user on a LAN address can't take a loopback connection: it doesn't count.
    expect(j(row("0100007F:1F9A", "0A", ME) + row("0101A8C0:1F9A", "0A", 1001))).toEqual({ ok: true });
    // Nothing on the port, or only on another port: no.
    expect(j(row("0100007F:1F9B", "0A", ME))).toMatchObject({ ok: false, why: expect.stringMatching(/nothing listens on port 8090/) });
    expect(j("")).toMatchObject({ ok: false });
  });

  it("loopback reach", () => {
    for (const a of ["*", "0.0.0.0", "::", "::1", "127.0.0.1", "127.1.2.3", "::ffff:127.0.0.1", "::ffff:0.0.0.0", "0:0:0:0:0:0:0:1"]) expect(reachesLoopback(a), a).toBe(true);
    for (const a of ["192.168.1.1", "10.0.0.1", "fe80::1", "::ffff:10.0.0.1", "128.0.0.1"]) expect(reachesLoopback(a), a).toBe(false);
  });
});

describe("macOS: netstat (all users) matched by this user's lsof", () => {
  const NETSTAT = (lines: string[]) =>
    ["Active Internet connections (including servers)", "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)", ...lines, "Active LOCAL (UNIX) domain sockets"].join("\n");
  const L = (proto: string, local: string, state = "LISTEN") => `${proto}       0      0  ${local.padEnd(23)}*.*                    ${state}`;

  it("parses both", () => {
    expect(parseNetstat(NETSTAT([L("tcp4", "127.0.0.1.8090"), L("tcp6", "::1.8090"), L("tcp46", "*.8090"), L("tcp4", "127.0.0.1.9", "ESTABLISHED")]))).toEqual([
      { addr: "127.0.0.1", port: 8090 },
      { addr: "::1", port: 8090 },
      { addr: "*", port: 8090 },
    ]);
    expect(parseNetstat("garbage")).toBeUndefined();
    expect(parseLsof("p42\nu501\nf7\nn127.0.0.1:8090\nf8\nn[::1]:8090\np43\nu0\nf3\nn*:8090\n")).toEqual([
      { addr: "127.0.0.1", port: 8090, pid: 42, uid: 501 },
      { addr: "::1", port: 8090, pid: 42, uid: 501 },
      { addr: "*", port: 8090, pid: 43, uid: 0 },
    ]);
  });

  it("every listener netstat shows needs one of this user's (or root's) at the same address", () => {
    const all = parseNetstat(NETSTAT([L("tcp4", "127.0.0.1.8090")]))!;
    expect(judgeDarwin(all, parseLsof("p1\nu501\nn127.0.0.1:8090\n"), 8090, 501)).toEqual({ ok: true });
    // A listener lsof can't see (another user's): refused.
    expect(judgeDarwin(all, [], 8090, 501)).toMatchObject({ ok: false, why: expect.stringMatching(/isn't yours/) });
    // Ours on 127.0.0.1, someone else's on ::1 (a `localhost` connection may go there): refused.
    const two = parseNetstat(NETSTAT([L("tcp4", "127.0.0.1.8090"), L("tcp6", "::1.8090")]))!;
    expect(judgeDarwin(two, parseLsof("p1\nu501\nn127.0.0.1:8090\n"), 8090, 501)).toMatchObject({ ok: false });
    // Two sockets at one address, only one ours (SO_REUSEPORT): refused.
    const dup = parseNetstat(NETSTAT([L("tcp4", "127.0.0.1.8090"), L("tcp4", "127.0.0.1.8090")]))!;
    expect(judgeDarwin(dup, parseLsof("p1\nu501\nn127.0.0.1:8090\n"), 8090, 501)).toMatchObject({ ok: false });
    // lsof naming another uid doesn't vouch.
    expect(judgeDarwin(all, parseLsof("p1\nu777\nn127.0.0.1:8090\n"), 8090, 501)).toMatchObject({ ok: false });
    expect(judgeDarwin([], [], 8090, 501)).toMatchObject({ ok: false, why: expect.stringMatching(/nothing listens/) });
  });
});

describe("checkLoopbackListener", () => {
  it("each platform's sources; failures, no port, Windows: no", async () => {
    const linux = (text: string) => checkLoopbackListener("http://localhost:8090", { platform: "linux", uid: ME, readFile: async (p) => (p.endsWith("6") ? "" : HEAD + text) });
    expect(await linux(row("0100007F:1F9A", "0A", ME))).toEqual({ ok: true });
    expect(await linux(row("0100007F:1F9A", "0A", 4242))).toMatchObject({ ok: false });
    expect(await checkLoopbackListener("http://localhost:8090", { platform: "linux", uid: ME, readFile: async () => Promise.reject(new Error("EACCES")) })).toMatchObject({ ok: false, why: expect.stringMatching(/couldn't read/) });
    const darwin = (net: string, lsof: string | Error) =>
      checkLoopbackListener("http://127.0.0.1:8090", { platform: "darwin", uid: 501, exec: async (c) => (c.endsWith("netstat") ? net : lsof instanceof Error ? Promise.reject(lsof) : lsof) });
    const net = "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\ntcp4       0      0  127.0.0.1.8090         *.*                    LISTEN\n";
    expect(await darwin(net, "p1\nu501\nn127.0.0.1:8090\n")).toEqual({ ok: true });
    expect(await darwin(net, new Error("exit 1"))).toMatchObject({ ok: false });
    expect(await darwin("", "p1\nu501\nn127.0.0.1:8090\n")).toMatchObject({ ok: false, why: expect.stringMatching(/netstat/) });
    expect(await checkLoopbackListener("http://localhost:8090", { platform: "win32", uid: 1 })).toMatchObject({ ok: false });
    expect(await checkLoopbackListener("not a url", { platform: "linux", uid: 1 })).toMatchObject({ ok: false });
    expect(endpointPort("https://localhost")).toBe(443);
    expect(endpointPort("http://localhost")).toBe(80);
  });

  it.skipIf(process.platform !== "linux" && process.platform !== "darwin")("the real check: this process's own listener is ok; a port nobody holds isn't", async (t) => {
    const server = createServer(() => {});
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
    const port = (server.address() as { port: number }).port;
    try {
      const v = await checkLoopbackListener(`http://127.0.0.1:${port}`);
      // A sandbox can hide the socket tables from child processes (then the check fails closed);
      // in CI the real check must see it.
      if (!v.ok && !process.env.CI) return t.skip();
      expect(v).toEqual({ ok: true });
    } finally {
      await new Promise((r) => server.close(r));
    }
    expect((await checkLoopbackListener(`http://127.0.0.1:${port}`)).ok).toBe(false);
  });
});
