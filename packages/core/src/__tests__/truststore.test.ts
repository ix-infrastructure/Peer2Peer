// Copyright 2026 Ix Infrastructure Inc.
import { afterAll, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { advanceWindow, mergeWindows } from "../replay.js";
import { FileDocBackend, FileTrustStore, LOCK_STALE_MS, MemoryTrustStore, defaultTrustDir, type TrustStore } from "../truststore.js";

const tmp = mkdtempSync(join(tmpdir(), "p2p-trust-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

const friendship = {
  inviter: "a@x",
  invitee: "b@y",
  inv: "inv1",
  aud: "*",
  iat: 1,
  inviteIat: 0,
  inviteDid: "d_a",
  acceptDid: "d_b",
  proof: { invite: "i", accept: "a" },
};

function suite(name: string, make: () => TrustStore) {
  describe(name, () => {
    it("rosters keep the highest ver", async () => {
      const s = make();
      expect(await s.putRoster({ iss: "a@x", sid: "s", ver: 2, jws: "r2" })).toBe("stored");
      expect(await s.putRoster({ iss: "a@x", sid: "s", ver: 1, jws: "r1" })).toBe("stale");
      expect(await s.putRoster({ iss: "a@x", sid: "s", ver: 2, jws: "r2" })).toBe("same");
      expect(await s.putRoster({ iss: "a@x", sid: "s", ver: 2, jws: "r2b" })).toBe("conflict");
      expect(await s.putRoster({ iss: "a@x", sid: "s", ver: 5, jws: "r5" })).toBe("stored");
      expect((await s.getRoster("a@x", "s"))?.jws).toBe("r5");
      expect(await s.getRoster("b@y", "s")).toBeUndefined();
    });

    it("friendships: idempotent, '*' invites bind once", async () => {
      const s = make();
      await s.addFriendship(friendship);
      await s.addFriendship(friendship);
      expect(await s.listFriendships()).toHaveLength(1);
      await expect(s.addFriendship({ ...friendship, invitee: "c@z" })).rejects.toThrow(/invite-already-bound/);
    });

    it("unfriends, revocations (newer only), replay, jwks, device certs", async () => {
      const s = make();
      await s.addUnfriend({ iss: "a@x", peer: "b@y", inv: "inv1", iat: 2, jws: "u" });
      await s.addUnfriend({ iss: "a@x", peer: "b@y", inv: "inv1", iat: 2, jws: "u" });
      expect(await s.listUnfriends()).toHaveLength(1);
      expect(await s.putRevocations({ iat: 10, dids: ["d_1"], jws: "r10", fetchedAt: 100 })).toBe(true);
      expect(await s.putRevocations({ iat: 5, dids: [], jws: "r5", fetchedAt: 200 })).toBe(false);
      expect(await s.getRevocations()).toMatchObject({ dids: ["d_1"], fetchedAt: 100 });
      // Re-polling the same list refreshes fetchedAt only.
      expect(await s.putRevocations({ iat: 10, dids: ["d_1"], jws: "r10", fetchedAt: 300 })).toBe(false);
      expect(await s.getRevocations()).toMatchObject({ iat: 10, fetchedAt: 300 });
      const w3 = advanceWindow(3, undefined);
      await s.putReplay("d_1", { nonces: ["n"], windows: { s: w3 } });
      expect(await s.getReplay("d_1")).toEqual({ nonces: ["n"], windows: { s: w3 } });
      // Merge, never overwrite (M1).
      const w1 = advanceWindow(1, undefined);
      await s.putReplay("d_1", { nonces: ["m"], windows: { s: w1 } });
      expect(await s.getReplay("d_1")).toEqual({ nonces: ["n", "m"], windows: { s: mergeWindows(w3, w1) } });
      await s.putJwks({ fetchedAt: 1, jwks: { keys: [] } });
      expect(await s.getJwks()).toEqual({ fetchedAt: 1, jwks: { keys: [] } });
      await s.putDeviceCert({ userId: "a@x", did: "d_1", exp: 100, jws: "c100" });
      await s.putDeviceCert({ userId: "a@x", did: "d_1", exp: 50, jws: "c50" });
      expect((await s.getDeviceCert("d_1"))?.jws).toBe("c100");
    });

    it("owner attestations keep the latest exp", async () => {
      const s = make();
      await s.putOwnerWorkspace({ userId: "o@x", exp: 200, jws: "w200" });
      await s.putOwnerWorkspace({ userId: "o@x", exp: 100, jws: "w100" });
      expect((await s.getOwnerWorkspace("o@x"))?.jws).toBe("w200");
      await s.putOwnerWorkspace({ userId: "o@x", exp: 300, jws: "w300" });
      expect((await s.getOwnerWorkspace("o@x"))?.jws).toBe("w300");
      expect(await s.getOwnerWorkspace("p@y")).toBeUndefined();
    });

    it("serialises concurrent writers", async () => {
      const s = make();
      await Promise.all(
        Array.from({ length: 20 }, (_, i) => s.addFriendship({ ...friendship, inv: `inv${i}` })),
      );
      expect(await s.listFriendships()).toHaveLength(20);
    });
  });
}

suite("MemoryTrustStore", () => new MemoryTrustStore());
let n = 0;
suite("FileTrustStore", () => new FileTrustStore(join(tmp, `store${n++}`, "p2p")));

describe("FileTrustStore on disk", () => {
  it("two stores on one directory (as two processes) don't lose updates", async () => {
    const dir = join(tmp, "shared", "p2p");
    const s1 = new FileTrustStore(dir);
    const s2 = new FileTrustStore(dir);
    await Promise.all(
      Array.from({ length: 20 }, (_, i) => (i % 2 ? s1 : s2).addFriendship({ ...friendship, inv: `inv${i}` })),
    );
    expect(await s1.listFriendships()).toHaveLength(20);
    // Concurrent replay admission across both: exactly one wins.
    const fields = { own: "a@x", sid: "s", seq: 1, ts: 1000, n: "nonce" };
    const verdicts = await Promise.all([s1.admitReplay("d_x", fields, 1000), s2.admitReplay("d_x", fields, 1000)]);
    expect(verdicts.filter((v) => v === undefined)).toHaveLength(1);
    expect(readdirSync(dir).filter((f) => f.startsWith("."))).toEqual([]);
  });

  it("breaks a stale lock left by a crashed process", async () => {
    const dir = join(tmp, "stale", "p2p");
    const s = new FileTrustStore(dir);
    await s.addFriendship(friendship);
    const lock = join(dir, ".lock");
    writeFileSync(lock, "999999\n");
    const old = new Date(Date.now() - LOCK_STALE_MS - 1000);
    utimesSync(lock, old, old);
    await s.addFriendship({ ...friendship, inv: "inv2" });
    expect(await s.listFriendships()).toHaveLength(2);
  });

  it("dir 0700, files 0600, no temp files left, persists across instances", async () => {
    const dir = join(tmp, "perm", "p2p");
    const s = new FileTrustStore(dir);
    await s.addFriendship(friendship);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(readdirSync(dir)).toEqual(["friendships.json"]);
    expect(statSync(join(dir, "friendships.json")).mode & 0o777).toBe(0o600);
    expect(await new FileTrustStore(dir).listFriendships()).toEqual([friendship]);
  });

  describe("lockfile (re-review LOW: lock races)", () => {
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    function tracker() {
      const t = { inside: 0, max: 0 };
      const body = (ms: number) => async () => {
        t.inside++;
        t.max = Math.max(t.max, t.inside);
        await sleep(ms);
        t.inside--;
      };
      return { t, body };
    }

    it("a write that fails (a full disk) leaves no temp file behind (soak)", async () => {
      const dir = join(tmp, "write-fails");
      const b = new FileDocBackend(dir);
      await b.write("doc", { ok: 1 });
      const fh = await (await import("node:fs/promises")).open(join(dir, "probe"), "w");
      const proto = Object.getPrototypeOf(fh) as { writeFile: (...a: unknown[]) => Promise<void> };
      await fh.close();
      const real = proto.writeFile;
      proto.writeFile = async () => {
        throw Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });
      };
      try {
        for (let i = 0; i < 3; i++) await expect(b.write("doc", { ok: 2 })).rejects.toThrow(/ENOSPC/);
      } finally {
        proto.writeFile = real;
      }
      expect(readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
      expect(await b.read("doc")).toEqual({ ok: 1 });
    });

    it("a slow live holder whose lock looks old is not broken", async () => {
      const dir = join(tmp, "lock-slow");
      const { t, body } = tracker();
      // Wait until A really holds it (a fixed 20 ms wasn't always enough under load: no lock yet).
      let holding!: () => void;
      const held = new Promise<void>((r) => (holding = r));
      const a = new FileDocBackend(dir).withLock(async () => {
        holding();
        await body(300)();
      });
      await held;
      const old = new Date(Date.now() - LOCK_STALE_MS - 1000);
      utimesSync(join(dir, ".lock"), old, old);
      const b = new FileDocBackend(dir).withLock(body(100));
      await sleep(100);
      const c = new FileDocBackend(dir).withLock(body(50));
      await Promise.all([a, b, c]);
      expect(t.max).toBe(1);
    });

    it("waiters racing to break a crashed holder's lock: one at a time", async () => {
      const dir = join(tmp, "lock-crashed");
      mkdirSync(dir, { recursive: true });
      const { t, body } = tracker();
      // A dead pid on this host: broken at once, whatever its age.
      writeFileSync(join(dir, ".lock"), JSON.stringify({ pid: 2 ** 22 + 12345, host: hostname(), token: "dead" }));
      await Promise.all(Array.from({ length: 8 }, () => new FileDocBackend(dir).withLock(body(30))));
      expect(t.max).toBe(1);
      // An old unreadable lock (legacy/garbage) is broken by age.
      writeFileSync(join(dir, ".lock"), "999999\n");
      const old = new Date(Date.now() - LOCK_STALE_MS - 1000);
      utimesSync(join(dir, ".lock"), old, old);
      await Promise.all(Array.from({ length: 8 }, () => new FileDocBackend(dir).withLock(body(10))));
      expect(t.max).toBe(1);
      expect(readdirSync(dir)).toEqual([]);
    });

    it("a lock never exists without its holder in it: a body write that fails leaves no lock (soak)", async () => {
      const dir = join(tmp, "lock-atomic");
      mkdirSync(dir, { recursive: true });
      const fsp = await import("node:fs/promises");
      // Fail every write of a lock body, however it is written (a full disk, or the process
      // exiting right after creating the file): before, an empty `.lock` stayed behind and held
      // every other process for LOCK_STALE_MS.
      const isLockBody = (d: unknown) => typeof d === "string" && /^\{"pid":\d+,"host":/.test(d);
      const enospc = () => Object.assign(new Error("ENOSPC: no space left on device, write"), { code: "ENOSPC" });
      const probe = await fsp.open(join(dir, "probe"), "w");
      const proto = Object.getPrototypeOf(probe) as { writeFile: (...a: unknown[]) => Promise<void> };
      await probe.close();
      rmSync(join(dir, "probe"));
      const realHandleWrite = proto.writeFile;
      const realWriteFile = fsp.default.writeFile;
      proto.writeFile = async function (this: unknown, d: unknown, ...rest: unknown[]) {
        if (isLockBody(d)) throw enospc();
        return realHandleWrite.call(this, d, ...rest);
      };
      fsp.default.writeFile = (async (path: unknown, d: unknown, ...rest: unknown[]) => {
        if (isLockBody(d)) throw enospc();
        return (realWriteFile as (...a: unknown[]) => Promise<void>)(path, d, ...rest);
      }) as typeof realWriteFile;
      try {
        await expect(new FileDocBackend(dir).withLock(async () => {})).rejects.toThrow(/ENOSPC/);
      } finally {
        proto.writeFile = realHandleWrite;
        fsp.default.writeFile = realWriteFile;
      }
      expect(readdirSync(dir)).toEqual([]);
      // And the next one gets the lock at once.
      const t0 = Date.now();
      await new FileDocBackend(dir, { timeoutMs: 1000 }).withLock(async () => {});
      expect(Date.now() - t0).toBeLessThan(500);
    });

    it("an empty lock (an older client's) is judged by LOCK_STALE_MS: a stalled creator a few seconds in keeps it (review M-B)", async () => {
      const dir = join(tmp, "lock-empty");
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, ".lock"), "");
      // A creator stalled 3 s between creating and writing it (or a server clock behind ours).
      const stalled = new Date(Date.now() - 3000);
      utimesSync(join(dir, ".lock"), stalled, stalled);
      await expect(new FileDocBackend(dir, { timeoutMs: 300 }).withLock(async () => {})).rejects.toThrow(/is locked/);
      expect(readFileSync(join(dir, ".lock"), "utf8")).toBe("");
      // Older than LOCK_STALE_MS: its creator is gone.
      const old = new Date(Date.now() - LOCK_STALE_MS - 1000);
      utimesSync(join(dir, ".lock"), old, old);
      const { t, body } = tracker();
      await Promise.all(Array.from({ length: 4 }, () => new FileDocBackend(dir, { timeoutMs: 2000 }).withLock(body(10))));
      expect(t.max).toBe(1);
      expect(readdirSync(dir)).toEqual([]);
    });

    // EPERM: a filesystem without hard links; EISDIR: what Windows reports on FAT and exFAT (review L1).
    it.each(["EPERM", "EISDIR"])("without hard links (%s) the lock still appears with its body (exclusive copy), never empty (review M-B)", async (code) => {
      const dir = join(tmp, `lock-nolinks-${code}`);
      const fsp = (await import("node:fs/promises")).default;
      const realLink = fsp.link;
      fsp.link = (async () => {
        throw Object.assign(new Error(`${code}: link`), { code });
      }) as typeof fsp.link;
      try {
        const { t, body } = tracker();
        const seen: string[] = [];
        await Promise.all(
          Array.from({ length: 4 }, () =>
            new FileDocBackend(dir).withLock(async () => {
              seen.push(readFileSync(join(dir, ".lock"), "utf8"));
              await body(10)();
            }),
          ),
        );
        expect(t.max).toBe(1);
        for (const raw of seen) expect(JSON.parse(raw)).toMatchObject({ pid: process.pid, host: hostname() });
      } finally {
        fsp.link = realLink;
      }
      expect(readdirSync(dir)).toEqual([]);
    });

    it("an EEXIST for a lock that holds our own token (an NFS retransmit) is ours (review L2)", async () => {
      const dir = join(tmp, "lock-nfs");
      const fsp = (await import("node:fs/promises")).default;
      const realLink = fsp.link;
      // The server made the link, but the reply to the retransmitted request is EEXIST.
      fsp.link = (async (a: string, b: string) => {
        await realLink(a, b);
        throw Object.assign(new Error("EEXIST: file already exists, link"), { code: "EEXIST" });
      }) as typeof fsp.link;
      try {
        const t0 = Date.now();
        let ran = false;
        await new FileDocBackend(dir, { timeoutMs: 1000 }).withLock(async () => {
          ran = true;
        });
        expect(ran).toBe(true);
        expect(Date.now() - t0).toBeLessThan(500);
      } finally {
        fsp.link = realLink;
      }
      expect(readdirSync(dir)).toEqual([]);
    });

    it("release only removes our own lock", async () => {
      const dir = join(tmp, "lock-token");
      const other = JSON.stringify({ pid: process.pid, host: hostname(), token: "someone-else" });
      await new FileDocBackend(dir).withLock(async () => {
        writeFileSync(join(dir, ".lock"), other); // e.g. taken over after a break
      });
      expect(readFileSync(join(dir, ".lock"), "utf8")).toBe(other);
      rmSync(join(dir, ".lock"));
    });

    it("refreshes the lock's mtime while held", async () => {
      const dir = join(tmp, "lock-refresh");
      const b = new FileDocBackend(dir, { refreshMs: 20 });
      await b.withLock(async () => {
        const old = new Date(Date.now() - 60_000);
        utimesSync(join(dir, ".lock"), old, old);
        await sleep(80);
        expect(Date.now() - statSync(join(dir, ".lock")).mtimeMs).toBeLessThan(1000);
      });
    });
  });

  it("defaults to ~/.ix/p2p", () => {
    expect(defaultTrustDir()).toMatch(/[/\\]\.ix[/\\]p2p$/);
  });
});
