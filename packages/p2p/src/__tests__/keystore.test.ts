// Copyright 2026 Ix Infrastructure Inc.
//
// Issue #8: the OS keychain backend for this device's keys (keystore.ts). Every test here runs the
// real keychain code against a stand-in for the OS tool (a Runner), never the real keychain: the
// stand-in records every command line, and no command line may ever hold key material. One opt-in
// test (P2P_TEST_REAL_KEYCHAIN=1, macOS) uses a throwaway keychain file.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, cpSync, existsSync, fstatSync, linkSync, mkdtempSync, openSync, readdirSync, readFileSync, readSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createDeviceCert, generateDeviceKeysV3, generateIdentityKey } from "@peer2peer/core/v3";
import { newKeysDoc } from "../app.js";
import { CliState, type KeysDoc } from "../state.js";
import {
  configuredBackend,
  finishPendingMove,
  keyStoreStatus,
  libsecretKeychain,
  macosKeychain,
  markerFile,
  moveKeysToFiles,
  moveKeysToKeychain,
  serviceFor,
  toolMessage,
  useKeychainForTests,
  windowsKeychain,
  WINDOWS_SCRIPT,
  payloadOf,
  realRunner,
  WINDOWS_CSHARP,
  WINDOWS_POWERSHELL,
  powershellPath,
  LABEL,
  SECURITY,
  KeychainError,
  type RunResult,
  type Runner,
} from "../keystore.js";
import { personTokenOk } from "../projects.js";
import { main } from "../cli.js";
import { startRelay, User, type TestRelay } from "./harness.js";

/** A stand-in for /usr/bin/security over an in-memory keychain, recording every call. */
class FakeSecurity {
  items = new Map<string, string>();
  calls: { file: string; args: string[]; input: string }[] = [];
  locked = false;
  /** The next store keeps a different value than it was given (a read-back must catch it). */
  corruptNext = false;
  readonly run: Runner = (file, args, input): RunResult => {
    this.calls.push({ file, args: [...args], input });
    if (file !== SECURITY) return { status: null, stdout: "", stderr: "", error: "ENOENT" };
    const opt = (a: readonly string[], f: string) => a[a.indexOf(f) + 1];
    if (args[0] === "-i") {
      const words = input.trim().split(/\s+/);
      if (words[0] !== "add-generic-password") return { status: 1, stdout: "", stderr: "unknown command" };
      if (this.locked) return { status: 152, stdout: "", stderr: "security: SecKeychainItemCreateFromContent: Unable to obtain authorization for this operation.\nadd-generic-password: returned -60008" };
      let v = opt(words, "-w");
      if (this.corruptNext) {
        v = `${v}x`;
        this.corruptNext = false;
      }
      this.items.set(`${opt(words, "-s")}|${opt(words, "-a")}`, v);
      return { status: 0, stdout: "", stderr: "" };
    }
    const key = `${opt(args, "-s")}|${opt(args, "-a")}`;
    if (args[0] === "find-generic-password") {
      if (this.locked) return { status: 36, stdout: "", stderr: "security: SecKeychainSearchCopyNext: User interaction is not allowed." };
      const v = this.items.get(key);
      return v === undefined ? { status: 44, stdout: "", stderr: "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain." } : { status: 0, stdout: `${v}\n`, stderr: "" };
    }
    if (args[0] === "delete-generic-password") {
      return this.items.delete(key) ? { status: 0, stdout: "", stderr: "" } : { status: 44, stdout: "", stderr: "not found" };
    }
    return { status: 1, stdout: "", stderr: "?" };
  };
  /** Every command line so far, as one string per call. */
  argv(): string[] {
    return this.calls.map((c) => [c.file, ...c.args].join(" "));
  }
}

/** The secrets of a keys document, and the forms they could leak in. */
function secretsOf(k: { spk: string; kpk: string; ik?: string }): string[] {
  return [k.spk, k.kpk, ...(k.ik ? [k.ik] : []), "p2p1."];
}

function expectNoSecretsIn(texts: string[], secrets: string[]): void {
  for (const t of texts) for (const s of secrets) expect(t.includes(s), `a command line held key material: ${s.slice(0, 6)}…`).toBe(false);
}

function makeKeys(): KeysDoc {
  const ik = generateIdentityKey();
  const device = generateDeviceKeysV3(ik.userId);
  const cert = createDeviceCert(ik, { signingPublicKey: device.signingPublicKey, agreementPublicKey: device.agreementPublicKey, label: "test" });
  return newKeysDoc(ik.userId, device, cert, ik);
}

const dirs: string[] = [];
const tmpHome = () => {
  const d = mkdtempSync(join(tmpdir(), "p2p-keystore-"));
  dirs.push(d);
  return d;
};
afterAll(() => {
  useKeychainForTests(undefined);
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

describe("the OS tools: secrets over stdin, never in a command line", () => {
  const secret = "p2p1.c2VjcmV0LXNlY3JldC1zZWNyZXQ";
  it("macOS: security -i reads the add command (and its secret) from stdin; reads and deletes name the item only", () => {
    const fake = new FakeSecurity();
    const kc = macosKeychain(fake.run, { exists: () => true });
    kc.set("peer2peer-keys-abc", "d_x", "Peer2Peer-device-keys", secret);
    expect(kc.get("peer2peer-keys-abc", "d_x")).toBe(secret);
    expect(kc.get("peer2peer-keys-abc", "d_other")).toBeUndefined();
    expect(kc.remove("peer2peer-keys-abc", "d_x")).toBe(true);
    expect(kc.remove("peer2peer-keys-abc", "d_x")).toBe(false);
    expect(fake.calls[0].args).toEqual(["-i"]);
    expect(fake.calls[0].input).toContain(`-w ${secret}`);
    // The access list: the security tool alone.
    expect(fake.calls[0].input).toContain(`-T ${SECURITY}`);
    expect(LABEL).toContain("peer2peer-keys");
    expect(fake.calls.every((c) => c.file === SECURITY)).toBe(true);
    expectNoSecretsIn(fake.argv(), [secret, "c2VjcmV0"]);
  });

  it("macOS: a locked keychain is an error naming no secret, not a missing item", () => {
    const fake = new FakeSecurity();
    fake.locked = true;
    const kc = macosKeychain(fake.run, { exists: () => true });
    expect(() => kc.get("peer2peer-keys-abc", "d_x")).toThrow(/locked/);
    try {
      kc.set("peer2peer-keys-abc", "d_x", "Peer2Peer-device-keys", secret);
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(secret);
    }
  });

  it("Linux: secret-tool store takes the secret on stdin; lookup's silence is 'no item', anything said is a failure", () => {
    const calls: { file: string; args: readonly string[]; input: string }[] = [];
    const store = new Map<string, string>();
    let fail = false;
    const run: Runner = (file, args, input) => {
      calls.push({ file, args, input });
      const key = `${args[args.indexOf("service") + 1]}|${args[args.indexOf("account") + 1]}`;
      if (fail) return { status: 1, stdout: "", stderr: "Cannot autolaunch D-Bus without X11 $DISPLAY" };
      if (args[0] === "store") {
        store.set(key, input);
        return { status: 0, stdout: "", stderr: "" };
      }
      if (args[0] === "lookup") return store.has(key) ? { status: 0, stdout: store.get(key)!, stderr: "" } : { status: 1, stdout: "", stderr: "" };
      if (args[0] === "clear") {
        store.delete(key);
        return { status: 0, stdout: "", stderr: "" };
      }
      return { status: 2, stdout: "", stderr: "" };
    };
    const kc = libsecretKeychain(run, { exists: (p) => p === "/usr/bin/secret-tool" });
    kc.set("peer2peer-keys-abc", "d_x", "Peer2Peer-device-keys", secret);
    expect(kc.get("peer2peer-keys-abc", "d_x")).toBe(secret);
    expect(kc.get("peer2peer-keys-abc", "d_y")).toBeUndefined();
    expect(kc.remove("peer2peer-keys-abc", "d_x")).toBe(true);
    expect(calls[0].input).toBe(secret);
    expect(calls.every((c) => c.file === "/usr/bin/secret-tool")).toBe(true);
    expectNoSecretsIn(
      calls.map((c) => [c.file, ...c.args].join(" ")),
      [secret, "c2VjcmV0"],
    );
    fail = true;
    expect(() => kc.get("peer2peer-keys-abc", "d_x")).toThrow(/Secret Service/);
    // Never found through PATH.
    expect(libsecretKeychain(run, { exists: () => false }).unavailable()).toMatch(/isn't installed/);
  });

  it("Windows: PowerShell by its absolute path; the script is in the command line, the secret only in the stdin request", () => {
    const calls: { file: string; args: readonly string[]; input: string }[] = [];
    const store = new Map<string, string>();
    const run: Runner = (file, args, input) => {
      calls.push({ file, args, input });
      const [op, target, account, label, sec] = input.split("\n");
      const req = { op, target, account, label, secret: sec };
      if (req.op === "set") store.set(req.target, req.secret);
      if (req.op === "get") return store.has(req.target) ? { status: 0, stdout: store.get(req.target)!, stderr: "" } : { status: 3, stdout: "", stderr: "" };
      if (req.op === "delete") return store.delete(req.target) ? { status: 0, stdout: "", stderr: "" } : { status: 3, stdout: "", stderr: "" };
      return { status: 0, stdout: "", stderr: "" };
    };
    const kc = windowsKeychain(run, { exists: () => true, env: { SystemRoot: "C:\\Windows" } });
    expect(kc.unavailable()).toBeUndefined();
    kc.set("peer2peer-keys-abc", "d_x", "Peer2Peer-device-keys", secret);
    expect(kc.get("peer2peer-keys-abc", "d_x")).toBe(secret);
    expect(kc.get("peer2peer-keys-abc", "d_y")).toBeUndefined();
    expect(kc.remove("peer2peer-keys-abc", "d_x")).toBe(true);
    expect(calls[0].file).toBe("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    const script = Buffer.from(calls[0].args[calls[0].args.indexOf("-EncodedCommand") + 1], "base64").toString("utf16le");
    expect(script).toBe(WINDOWS_SCRIPT);
    expect(script).toContain("c.Persist = 2");
    expect(calls[0].args).toContain("-NoProfile");
    expect(script).toContain("$PSModuleAutoloadingPreference = 'None'");
    expectNoSecretsIn(
      calls.map((c) => [c.file, ...c.args, Buffer.from(c.args.at(-1)!, "base64").toString("utf16le")].join(" ")),
      [secret, "c2VjcmV0"],
    );
    // An environment that names a strange SystemRoot doesn't move where PowerShell is run from.
    const odd = windowsKeychain(run, { exists: () => true, env: { SystemRoot: "\\\\evil\\share" } });
    odd.get("peer2peer-keys-abc", "d_x");
    expect(calls.at(-1)!.file).toBe("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  });

  it("Windows: the fixed PowerShell path first; %SystemRoot% only when it is a drive's Windows folder, never a user profile", () => {
    const only = (p: string) => (q: string) => q === p;
    expect(powershellPath({ SystemRoot: "D:\\Users\\sam\\evil" }, () => true)).toBe(WINDOWS_POWERSHELL);
    expect(powershellPath({ SystemRoot: "D:\\Windows" }, only("D:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"))).toBe("D:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    for (const root of ["C:\\Users\\sam\\Windows", "D:\\Users\\sam", "\\\\server\\Windows", "D:\\Windows\\..\\Users\\sam"]) {
      expect(powershellPath({ SystemRoot: root, windir: root }, () => false), root).toBeUndefined();
      expect(powershellPath({ SystemRoot: root }, (q) => q.startsWith(root)), root).toBeUndefined();
    }
    const none = windowsKeychain(() => ({ status: 0, stdout: "", stderr: "" }), { exists: () => false, env: { SystemRoot: "C:\\Users\\x" } });
    expect(none.unavailable()).toMatch(/isn't at/);
    expect(() => none.get("peer2peer-keys-abc", "d_x")).toThrow(KeychainError);
  });

  it("Windows: the C# helper has no line break inside a string or char literal (CS1010), and compiles where a C# compiler is installed", () => {
    for (const line of WINDOWS_CSHARP.split("\n")) {
      // Every quote on a line is closed on that line.
      const bare = line.replace(/\\./g, "");
      expect((bare.match(/'/g) ?? []).length % 2, line).toBe(0);
      expect((bare.match(/"/g) ?? []).length % 2, line).toBe(0);
    }
    const mcs = ["/usr/bin/mcs", "/usr/local/bin/mcs", "/opt/homebrew/bin/mcs"].find((p) => existsSync(p));
    if (!mcs) return;
    const dir = tmpHome();
    writeFileSync(join(dir, "P2PCred.cs"), WINDOWS_CSHARP);
    execFileSync(mcs, ["-target:library", `-out:${join(dir, "P2PCred.dll")}`, join(dir, "P2PCred.cs")], { stdio: "pipe" });
    expect(existsSync(join(dir, "P2PCred.dll"))).toBe(true);
  });

  it("Windows (M1): the secret never passes through a cmdlet or a PowerShell variable: only the C# reads stdin and writes the answer", () => {
    const ps = WINDOWS_SCRIPT.replace(WINDOWS_CSHARP, "");
    expect(WINDOWS_SCRIPT).toContain(WINDOWS_CSHARP);
    // No cmdlet at all in the loader (Verb-Noun), not even Add-Type, and no pipeline.
    expect(ps).not.toMatch(/\b[A-Z][a-z]+-[A-Z][A-Za-z]+\b/);
    expect(ps).not.toMatch(/\|/);
    expect(ps).not.toMatch(/ConvertFrom-Json|Add-Type|ReadToEnd|\[Console\]::In|\$req|secret/i);
    // The C# reads the request and writes the secret itself.
    expect(WINDOWS_CSHARP).toContain("Console.In.ReadToEnd()");
    expect(WINDOWS_CSHARP).toContain("Console.Out.Write(s)");
  });

  it("item names and secrets outside the narrow alphabet are refused before any tool runs", () => {
    const fake = new FakeSecurity();
    const kc = macosKeychain(fake.run, { exists: () => true });
    expect(() => kc.set("svc -w x", "d_x", "l", secret)).toThrow();
    expect(() => kc.set("svc", "d_x", "l", "-w injected")).toThrow();
    expect(() => kc.get("svc\nfind", "d_x")).toThrow();
    // I1: nothing that could be read as an option.
    expect(() => kc.get("-svc", "d_x")).toThrow(KeychainError);
    expect(() => kc.get("svc", "-a")).toThrow(KeychainError);
    expect(() => kc.set("svc", "d_x", "-T", secret)).toThrow(KeychainError);
    expect(fake.calls).toHaveLength(0);
  });

  it("a tool's message is shown without anything shaped like a secret", () => {
    expect(toolMessage("failed for p2p1.abcDEF_- here", "p2p1.abcDEF_-")).not.toContain("abcDEF");
    expect(toolMessage("x p2p1.zzzz y")).not.toContain("zzzz");
    expect(toolMessage("A".repeat(43))).not.toContain("A".repeat(43));
  });
});

describe("the key store: moves, read-back, fail closed", () => {
  let fake: FakeSecurity;
  beforeEach(() => {
    fake = new FakeSecurity();
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
  });

  it("moves keys into the keychain only after a byte-for-byte read-back, overwrites the old file, and back again", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    // Another name for the old file (a backup tool's hard link). On POSIX the old file is zeroed through
    // the handle held across the rename, so that name's bytes are overwritten too. On Windows the old file
    // is zeroed through a wipe name only when it has no other name (nlink 1), so this one keeps its bytes.
    const other = join(home, "keys-link.json");
    linkSync(join(home, "cli", "keys.json"), other);
    const otherBytes = readFileSync(other);

    const r = await moveKeysToKeychain(st.keyStore);
    expect(r).toMatchObject({ backend: "keychain", moved: true });
    const onDisk = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")) as Record<string, unknown>;
    expect(onDisk).toMatchObject({ userId: keys.userId, did: keys.did, cert: keys.cert, store: "keychain", service: serviceFor(home) });
    for (const f of ["spk", "kpk", "ik"]) expect(onDisk[f] === undefined, f).toBe(true);
    expect(readFileSync(other).equals(process.platform === "win32" ? otherBytes : Buffer.alloc(otherBytes.length, 0))).toBe(true);
    expect(JSON.parse(readFileSync(markerFile(home), "utf8"))).toMatchObject({ backend: "keychain", service: serviceFor(home) });
    // Loads give the same keys.
    expect(await st.get("keys")).toEqual(keys);
    expect(await new CliState(home).get("keys")).toEqual(keys);
    // No command line ever held them.
    expectNoSecretsIn(fake.argv(), secretsOf(keys));
    expect(keyStoreStatus(home)).toMatchObject({ configured: "keychain", keys: "keychain", readable: true, item: { service: serviceFor(home), account: keys.did } });

    // A write of the same secrets (a renewed certificate) leaves the item alone, never updates it in
    // place (on macOS that asks for the user's OK in a dialog); keys.json stays sealed.
    const adds = () => fake.calls.filter((c) => c.args[0] === "-i").length;
    const before = adds();
    await new CliState(home).put("keys", { ...keys, cert: `${keys.cert}` });
    expect(adds()).toBe(before);
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    // Other secrets under this device's name over a sealed keys.json: refused (the item may be their only copy).
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).put("keys", { ...keys, kpk: makeKeys().kpk })).rejects.toMatchObject({ code: "keychain_mismatch" });
    expect(await new CliState(home).get("keys")).toEqual(keys);

    const back = await moveKeysToFiles(st.keyStore);
    expect(back).toMatchObject({ backend: "file", moved: true });
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8"))).toEqual(keys);
    expect(fake.items.size).toBe(0);
    expect(configuredBackend(home)).toBe("file");
    expectNoSecretsIn(fake.argv(), secretsOf(keys));
  });

  it("the Windows way of overwriting the old file (no open handle across the rename): a second name, zeroed and removed after", async () => {
    const real = Object.getOwnPropertyDescriptor(process, "platform")!;
    // On Windows itself a handle held open would block the rename this test is about: no handle there.
    const watch = process.platform !== "win32";
    Object.defineProperty(process, "platform", { value: "win32" });
    try {
      const home = tmpHome();
      const st = new CliState(home);
      const keys = makeKeys();
      await st.put("keys", keys);
      // A handle on the old file shows its bytes after it is gone from every name.
      const fd = watch ? openSync(join(home, "cli", "keys.json"), "r") : -1;
      const size = watch ? fstatSync(fd).size : 0;
      // One left by an interrupted run is finished too.
      writeFileSync(join(home, "cli", ".keys.json.wipe-left"), "secret bytes");
      await moveKeysToKeychain(st.keyStore);
      if (watch) {
        const after = Buffer.alloc(size);
        readSync(fd, after, 0, size, 0);
        closeSync(fd);
        expect(after.equals(Buffer.alloc(size, 0))).toBe(true);
      }
      expect(readdirSync(join(home, "cli")).filter((f) => f.includes("wipe"))).toEqual([]);
      expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    } finally {
      Object.defineProperty(process, "platform", real);
    }
  });

  it("wipe files left by an interrupted move: removed on the next writable load, reported until then; zeroed only when safe", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    const cli = join(home, "cli");
    const keysFile = join(cli, "keys.json");
    const keysBytes = readFileSync(keysFile);
    // 1. A plain leftover (nlink 1, not keys.json): zeroed, then removed.
    writeFileSync(join(cli, ".keys.json.wipe-plain"), "old secret bytes");
    // (Not on Windows, where a file removed while open keeps its name until the handle closes.)
    const win = process.platform === "win32";
    const fd = win ? -1 : openSync(join(cli, ".keys.json.wipe-plain"), "r");
    // 2. A second name of keys.json itself (a run that linked but hasn't renamed yet): only unlinked.
    linkSync(keysFile, join(cli, ".keys.json.wipe-same"));
    // 3. A symbolic link to a file elsewhere: removed, never followed.
    const outside = join(home, "outside.txt");
    writeFileSync(outside, "not p2p's");
    let linked = true;
    try {
      symlinkSync(outside, join(cli, ".keys.json.wipe-link"));
    } catch {
      // Windows without the symlink privilege
      linked = false;
    }
    // 4. A file with another name elsewhere (nlink 2): removed, its other name keeps its bytes.
    const shared = join(home, "shared.txt");
    writeFileSync(shared, "someone else's");
    linkSync(shared, join(cli, ".keys.json.wipe-shared"));

    const status = keyStoreStatus(home);
    expect(status.leftovers?.sort()).toEqual([...(linked ? [".keys.json.wipe-link"] : []), ".keys.json.wipe-plain", ".keys.json.wipe-same", ".keys.json.wipe-shared"]);
    expect(status.problem).toMatch(/interrupted move/);
    // A read-only look leaves them.
    expect(readdirSync(cli).filter((f) => f.includes("wipe"))).toHaveLength(linked ? 4 : 3);

    expect(await finishPendingMove(st.keyStore)).toBeUndefined();
    expect(readdirSync(cli).filter((f) => f.includes("wipe"))).toEqual([]);
    if (!win) {
      const plain = Buffer.alloc(16);
      readSync(fd, plain, 0, 16, 0);
      closeSync(fd);
      expect(plain.equals(Buffer.alloc(16, 0))).toBe(true);
    }
    expect(readFileSync(keysFile).equals(keysBytes)).toBe(true);
    expect(readFileSync(outside, "utf8")).toBe("not p2p's");
    expect(readFileSync(shared, "utf8")).toBe("someone else's");
    expect(keyStoreStatus(home).leftovers).toBeUndefined();

    // `keys backend file` sweeps them too.
    writeFileSync(join(cli, ".keys.json.wipe-again"), "x");
    await moveKeysToFiles(st.keyStore);
    expect(readdirSync(cli).filter((f) => f.includes("wipe"))).toEqual([]);
  });

  it("a read-back that differs leaves everything as it was", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    const before = readFileSync(join(home, "cli", "keys.json"), "utf8");
    fake.corruptNext = true;
    await expect(moveKeysToKeychain(st.keyStore)).rejects.toMatchObject({ code: "keychain_write_failed" });
    expect(readFileSync(join(home, "cli", "keys.json"), "utf8")).toBe(before);
    expect(existsSync(markerFile(home))).toBe(false);
  });

  it("an interrupted move (marker written, keys.json not sealed yet) is finished by running it again", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    writeFileSync(markerFile(home), JSON.stringify({ v: 1, backend: "keychain" }));
    // The secrets in keys.json are the keys meanwhile.
    expect(await st.get("keys")).toEqual(keys);
    expect(keyStoreStatus(home).problem).toMatch(/hasn't finished/);
    await moveKeysToKeychain(st.keyStore);
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    expect(await new CliState(home).get("keys")).toEqual(keys);
    // Again: nothing to do.
    expect((await moveKeysToKeychain(st.keyStore)).moved).toBe(false);
  });

  it("L3: a move that stopped before keys.json was sealed, then `keys backend file`: the copy in the keychain is deleted", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    // The move stored the item and wrote the marker, then stopped.
    fake.items.set(`${serviceFor(home)}|${keys.did}`, payloadOf({ ...keys }));
    writeFileSync(markerFile(home), JSON.stringify({ v: 1, backend: "keychain" }));
    const r = await moveKeysToFiles(st.keyStore);
    expect(r).toMatchObject({ backend: "file", moved: false });
    expect(fake.items.size).toBe(0);
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8"))).toEqual(keys);
    // Not when keys.json's keys aren't this device's (a damaged file): the item stays.
    const st2 = new CliState(tmpHome());
    const k2 = makeKeys();
    await st2.put("keys", { ...k2, spk: makeKeys().spk });
    fake.items.set(`${serviceFor(st2.dir)}|${k2.did}`, "p2p1.keep");
    await moveKeysToFiles(st2.keyStore);
    expect(fake.items.get(`${serviceFor(st2.dir)}|${k2.did}`)).toBe("p2p1.keep");
    // Nor an item under this device's name that isn't a copy of keys.json's keys: kept, with a warning.
    const st3 = new CliState(tmpHome());
    const k3 = makeKeys();
    await st3.put("keys", k3);
    fake.items.set(`${serviceFor(st3.dir)}|${k3.did}`, "p2p1.other");
    const r3 = await moveKeysToFiles(st3.keyStore);
    expect(fake.items.get(`${serviceFor(st3.dir)}|${k3.did}`)).toBe("p2p1.other");
    expect(r3.warnings.join(" ")).toMatch(/left alone/);
  });

  it("an empty home: `keys backend keychain` stores, reads back and deletes a probe item before it records the choice", async () => {
    const home = tmpHome();
    const r = await moveKeysToKeychain(new CliState(home).keyStore);
    expect(r.moved).toBe(false);
    const probes = fake.calls.filter((c) => c.args[0] === "-i");
    expect(probes).toHaveLength(1);
    expect(probes[0].input).toMatch(/-a probe-[0-9a-f]{16} /);
    expect(fake.items.size).toBe(0);
    expect(configuredBackend(home)).toBe("keychain");
    // A keychain that can't store: no marker.
    const locked = tmpHome();
    fake.locked = true;
    await expect(moveKeysToKeychain(new CliState(locked).keyStore)).rejects.toMatchObject({ code: "keychain_write_failed" });
    expect(existsSync(markerFile(locked))).toBe(false);
    fake.locked = false;
    // One that reads back something else: no marker, and the probe is gone.
    const odd = tmpHome();
    fake.corruptNext = true;
    await expect(moveKeysToKeychain(new CliState(odd).keyStore)).rejects.toMatchObject({ code: "keychain_write_failed" });
    expect(existsSync(markerFile(odd))).toBe(false);
    expect(fake.items.size).toBe(0);
  });

  it("L4: sealed keys stay in the keychain when keystore.json is missing or says files: an ordinary write never unseals them", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    await moveKeysToKeychain(st.keyStore);
    for (const marker of [undefined, JSON.stringify({ v: 1, backend: "file" })]) {
      if (marker === undefined) rmSync(markerFile(home));
      else writeFileSync(markerFile(home), marker);
      // A renewed certificate.
      await new CliState(home).put("keys", { ...keys, cert: keys.cert });
      const onDisk = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")) as Record<string, unknown>;
      expect(onDisk.spk === undefined).toBe(true);
      expect(onDisk.store).toBe("keychain");
      expect(await new CliState(home).get("keys")).toEqual(keys);
      expect(keyStoreStatus(home)).toMatchObject({ keys: "keychain", readable: true, problem: expect.stringMatching(/stay in the keychain/) });
    }
    // And with the keychain locked, the write fails instead of falling back to the file.
    fake.locked = true;
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).put("keys", keys)).rejects.toThrow();
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
  });

  it("I2: an item whose agreement key isn't the certificate's, or an identity key in keys.json that isn't this identity's, is refused", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    await moveKeysToKeychain(st.keyStore);
    const key = `${serviceFor(home)}|${keys.did}`;
    const good = fake.items.get(key)!;
    const body = JSON.parse(Buffer.from(good.slice(5), "base64url").toString("utf8")) as Record<string, unknown>;
    const enc = (o: unknown) => `p2p1.${Buffer.from(JSON.stringify(o)).toString("base64url")}`;
    fake.items.set(key, enc({ ...body, kpk: makeKeys().kpk }));
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_mismatch" });
    // An item without the identity key, and keys.json carrying another identity's: refused.
    const { ik: _ik, ...noIk } = body;
    void _ik;
    fake.items.set(key, enc(noIk));
    const sealed = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")) as Record<string, unknown>;
    writeFileSync(join(home, "cli", "keys.json"), JSON.stringify({ ...sealed, ik: makeKeys().ik }));
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_mismatch" });
    // This identity's own one in keys.json is taken.
    writeFileSync(join(home, "cli", "keys.json"), JSON.stringify({ ...sealed, ik: keys.ik }));
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    expect(await new CliState(home).get("keys")).toEqual(keys);
    fake.items.set(key, good);
  });

  it("fails closed: locked, item gone, another device's item, a copied home; never new keys", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    await moveKeysToKeychain(st.keyStore);
    const sealed = readFileSync(join(home, "cli", "keys.json"), "utf8");

    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    fake.locked = true;
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_unreadable" });
    await expect(moveKeysToFiles(new CliState(home).keyStore)).rejects.toMatchObject({ code: "keychain_unreadable" });
    expect(keyStoreStatus(home)).toMatchObject({ keys: "keychain", readable: false });
    fake.locked = false;

    const item = [...fake.items.entries()][0];
    fake.items.clear();
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_missing" });

    // Another device's secrets under this device's name.
    const otherKeys = makeKeys();
    const st2 = new CliState(tmpHome());
    await st2.put("keys", otherKeys);
    writeFileSync(markerFile(st2.dir), JSON.stringify({ v: 1, backend: "keychain" }));
    await moveKeysToKeychain(st2.keyStore);
    fake.items.set(item[0], fake.items.get(`${serviceFor(st2.dir)}|${otherKeys.did}`)!);
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_mismatch" });
    fake.items.set(item[0], item[1]);

    // The tool missing.
    useKeychainForTests(macosKeychain(fake.run, { exists: () => false }));
    await expect(new CliState(home).get("keys")).rejects.toMatchObject({ code: "keychain_unavailable" });
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));

    // A copy of the home elsewhere names another home's item: refused, never the other home's keys.
    const copy = tmpHome();
    cpSync(home, copy, { recursive: true });
    expect(serviceFor(copy)).not.toBe(serviceFor(home));
    await expect(new CliState(copy).get("keys")).rejects.toMatchObject({ code: "keychain_moved" });

    // Through all of it keys.json was never rewritten.
    expect(readFileSync(join(home, "cli", "keys.json"), "utf8")).toBe(sealed);
    expect(await new CliState(home).get("keys")).toEqual(keys);
  });

  it("new keys on a home that chose the keychain go straight there; a damaged marker stops a write", async () => {
    const home = tmpHome();
    const st = new CliState(home);
    expect((await moveKeysToKeychain(st.keyStore)).moved).toBe(false);
    const keys = makeKeys();
    await st.put("keys", keys);
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    expect(await st.get("keys")).toEqual(keys);
    // Sealed keys stay sealed whatever the marker holds; keys in a file aren't written past a damaged one.
    writeFileSync(markerFile(home), "{not json");
    await st.put("keys", keys);
    expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    const plain = new CliState(tmpHome());
    await plain.put("keys", keys);
    writeFileSync(markerFile(plain.dir), "{not json");
    await expect(plain.put("keys", keys)).rejects.toMatchObject({ code: "keystore_unreadable" });
  });
});

describe("through the CLI", () => {
  const R = "wss://relay-keystore.test/v3";
  let relay: TestRelay;
  let tr: Record<string, string>;
  const users: User[] = [];
  let fake: FakeSecurity;
  beforeAll(async () => {
    relay = await startRelay(R, { limits: { identityPublishPerIpPerHour: 100_000, newDevicesPerIpPerDay: 100_000, newDevicesPerIpv4PerDay: 100_000 } });
    tr = { [R]: `ws://127.0.0.1:${relay.port}/v3` };
  });
  afterAll(async () => {
    await relay?.close();
    for (const u of users) u.cleanup();
  });
  beforeEach(() => {
    fake = new FakeSecurity();
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
  });
  const mk = (name: string) => {
    const u = new User(name, tr, { P2P_DEFAULT_RELAYS: R });
    users.push(u);
    return u;
  };

  it("keys backend keychain: person only; then every command works from the keychain, the person token still verifies, doctor says where", async () => {
    const u = mk("ks-cli");
    const me = await u.ok(["init", "--name", "kscli", "--relay", R, "--yes"]);
    expect((await u.ok(["keys", "backend"])).keys).toBe("file");
    const keysBefore = JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as KeysDoc;
    // An agent can't flip it, whatever its terminal would answer.
    const out: string[] = [];
    const code = await main(["keys", "backend", "keychain", "--json"], { env: { ...u.env, P2P_PERSON_TOKEN: "", CLAUDECODE: "1" }, io: { out: (l) => out.push(l), err: () => {} }, confirmTty: async () => true });
    process.exitCode = 0;
    expect(code).toBe(1);
    expect((JSON.parse(out.at(-1) ?? "{}") as Record<string, unknown>).error).toBe("refused");
    expect(existsSync(markerFile(u.home))).toBe(false);
    expect(fake.calls).toHaveLength(0);

    const moved = await u.ok(["keys", "backend", "keychain"]);
    expect(moved).toMatchObject({ backend: "keychain", moved: true });
    const sealed = JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")) as Record<string, unknown>;
    expect(sealed.spk === undefined).toBe(true);
    expect((await u.ok(["whoami"])).userId).toBe(me.userId);
    expect(personTokenOk({ P2P_PERSON_TOKEN: u.personToken }, u.home)).toBe(true);
    const doc = await u.ok(["doctor"]);
    const ks = (doc.checks as { id: string; status: string; detail: string }[]).find((c) => c.id === "key-storage")!;
    expect(ks.status).toBe("ok");
    expect(ks.detail).toContain("macOS Keychain");
    expectNoSecretsIn(fake.argv(), secretsOf(keysBefore));
    expect(JSON.stringify(doc)).not.toContain(keysBefore.spk);

    // Locked: commands that need the keys stop with the keychain's error (not "stale token", not a new identity).
    fake.locked = true;
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));
    const locked = await u.run(["whoami"]);
    expect(locked.code).toBe(1);
    expect(locked.json.error).toBe("keychain_unreadable");
    expect(String(locked.json.reason)).toMatch(/no new keys were made/);
    const ldoc = await u.ok(["doctor"]).catch(async () => (await u.run(["doctor"])).json);
    const lks = (ldoc.checks as { id: string; status: string }[]).find((c) => c.id === "key-storage")!;
    expect(lks.status).toBe("fail");
    expect((ldoc.checks as { id: string; detail: string }[]).find((c) => c.id === "identity")!.detail).not.toMatch(/no Peer2Peer identity yet/);
    expect((await u.run(["init", "--name", "again", "--relay", R, "--yes"])).code).toBe(1);
    expect(JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8"))).toEqual(sealed);
    fake.locked = false;
    useKeychainForTests(macosKeychain(fake.run, { exists: () => true }));

    // And back to files.
    expect(await u.ok(["keys", "backend", "file"])).toMatchObject({ backend: "file", moved: true });
    expect(JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8"))).toEqual(keysBefore);
    expect((await u.ok(["whoami"])).userId).toBe(me.userId);
    expectNoSecretsIn(fake.argv(), secretsOf(keysBefore));
  });

  it("a home that chose the keychain and holds keys in keys.json (a rotation's swap, an interrupted move): the next command moves them; a read-only one doesn't", async () => {
    const u = mk("ks-pending");
    await u.ok(["init", "--name", "kspend", "--relay", R, "--yes"]);
    writeFileSync(markerFile(u.home), JSON.stringify({ v: 1, backend: "keychain" }));
    await u.ok(["doctor"]);
    expect(JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")).spk !== undefined).toBe(true);
    await u.ok(["whoami"]);
    expect(JSON.parse(readFileSync(join(u.home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
    expect(fake.items.size).toBe(1);
    // The keychain unusable: the command still runs from keys.json, with a warning.
    const u2 = mk("ks-pending2");
    await u2.ok(["init", "--name", "kspend2", "--relay", R, "--yes"]);
    writeFileSync(markerFile(u2.home), JSON.stringify({ v: 1, backend: "keychain" }));
    fake.locked = true;
    const r = await u2.run(["whoami"]);
    expect(r.code).toBe(0);
    expect(r.err).toMatch(/still in .*keys\.json/);
    expect(JSON.parse(readFileSync(join(u2.home, "cli", "keys.json"), "utf8")).spk !== undefined).toBe(true);
  });

  it("two homes on one machine never share an item", async () => {
    const a = mk("ks-a");
    const b = mk("ks-b");
    await a.ok(["init", "--name", "ksa", "--relay", R, "--yes"]);
    await b.ok(["init", "--name", "ksb", "--relay", R, "--yes"]);
    await a.ok(["keys", "backend", "keychain"]);
    await b.ok(["keys", "backend", "keychain"]);
    expect(fake.items.size).toBe(2);
    expect(new Set([...fake.items.keys()].map((k) => k.split("|")[0])).size).toBe(2);
    expect((await a.ok(["whoami"])).name).toBe("ksa");
    expect((await b.ok(["whoami"])).name).toBe("ksb");
  });
});

// Opt-in: the real Windows Credential Manager through powershell.exe -EncodedCommand, stdin and the
// compiled C# helper, end to end (CI's windows job). A throwaway service unique to the run, deleted after.
// Secrets are compared as booleans only, so a failure never prints one.
describe.runIf(process.env.P2P_TEST_REAL_CREDMAN === "1" && process.platform === "win32")("the real Windows Credential Manager (opt-in)", () => {
  const service = process.env.P2P_TEST_KEYCHAIN_SERVICE || `peer2peer-keys-test-${randomBytes(6).toString("hex")}`;
  afterAll(() => {
    try {
      windowsKeychain().remove(service, "d_test");
    } catch {
      // gone already
    }
  });

  it("stores, reads back, and deletes a credential; PowerShell leaves stdin to the helper", () => {
    useKeychainForTests(undefined);
    const calls: { input: string }[] = [];
    const run: Runner = (file, args, input) => {
      calls.push({ input });
      return realRunner(file, args, input);
    };
    const kc = windowsKeychain(run);
    expect(kc.unavailable()).toBeUndefined();
    const secret = `p2p1.${randomBytes(32).toString("base64url")}`;
    expect(kc.get(service, "d_test") === undefined).toBe(true);
    kc.set(service, "d_test", LABEL, secret);
    // The whole secret came back: the helper read every line of stdin (PowerShell consumed none of it).
    const back = kc.get(service, "d_test");
    expect(back === secret).toBe(true);
    // Overwritten in place (CredWrite replaces a generic credential).
    const second = `p2p1.${randomBytes(32).toString("base64url")}`;
    kc.set(service, "d_test", LABEL, second);
    expect(kc.get(service, "d_test") === second).toBe(true);
    expect(kc.remove(service, "d_test")).toBe(true);
    expect(kc.get(service, "d_test") === undefined).toBe(true);
    expect(kc.remove(service, "d_test")).toBe(false);
    expect(calls.length).toBeGreaterThan(0);
  });

  it("a whole move into the Credential Manager and back, through the key store", async () => {
    useKeychainForTests(windowsKeychain());
    const home = tmpHome();
    const st = new CliState(home);
    const keys = makeKeys();
    await st.put("keys", keys);
    try {
      expect((await moveKeysToKeychain(st.keyStore)).moved).toBe(true);
      expect(JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8")).spk === undefined).toBe(true);
      useKeychainForTests(windowsKeychain());
      // Same fields, same values (in any order), compared without printing either.
      const canon = (o: unknown) => JSON.stringify(Object.entries(o as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)));
      expect(canon(await new CliState(home).get("keys")) === canon(keys)).toBe(true);
      expect((await moveKeysToFiles(st.keyStore)).moved).toBe(true);
      expect(windowsKeychain().get(serviceFor(home), keys.did) === undefined).toBe(true);
    } finally {
      try {
        windowsKeychain().remove(serviceFor(home), keys.did);
      } catch {
        // gone already
      }
      useKeychainForTests(undefined);
    }
  });
});

// Opt-in: the real /usr/bin/security against a throwaway keychain file (never the login keychain).
describe.runIf(process.env.P2P_TEST_REAL_KEYCHAIN === "1" && process.platform === "darwin")("the real macOS security tool (opt-in)", () => {
  it("stores, reads back, and deletes an item in a throwaway keychain", () => {
    const dir = tmpHome();
    const file = join(dir, "p2p-test.keychain-db");
    execFileSync(SECURITY, ["create-keychain", "-p", "p2p-test", file]);
    try {
      execFileSync(SECURITY, ["unlock-keychain", "-p", "p2p-test", file]);
      const kc = macosKeychain(undefined, { keychainFile: file });
      const secret = `p2p1.${Buffer.from("opt-in test").toString("base64url")}`;
      expect(kc.get("peer2peer-keys-optin", "d_test")).toBeUndefined();
      kc.set("peer2peer-keys-optin", "d_test", "Peer2Peer-device-keys", secret);
      expect(kc.get("peer2peer-keys-optin", "d_test")).toBe(secret);
      // An existing item is never updated in place (that asks for the user's OK in a dialog): deleted, then added.
      expect(() => kc.set("peer2peer-keys-optin", "d_test", "Peer2Peer-device-keys", `${secret}A`)).toThrow();
      expect(kc.remove("peer2peer-keys-optin", "d_test")).toBe(true);
      kc.set("peer2peer-keys-optin", "d_test", "Peer2Peer-device-keys", `${secret}A`);
      expect(kc.get("peer2peer-keys-optin", "d_test")).toBe(`${secret}A`);
      expect(kc.remove("peer2peer-keys-optin", "d_test")).toBe(true);
      expect(kc.get("peer2peer-keys-optin", "d_test")).toBeUndefined();
      // A locked keychain: reading an item is an error, never "no item".
      kc.set("peer2peer-keys-optin", "d_test", "Peer2Peer-device-keys", secret);
      execFileSync(SECURITY, ["lock-keychain", file]);
      expect(() => kc.get("peer2peer-keys-optin", "d_test")).toThrow(KeychainError);
    } finally {
      execFileSync(SECURITY, ["delete-keychain", file]);
    }
  });
});
