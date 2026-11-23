// Copyright 2026 Ix Infrastructure Inc.
//
// Where this device's secret keys live (issue #8): in `<home>/cli/keys.json` (0600, the default), or
// in the OS keychain (macOS Keychain, Windows Credential Manager, libsecret on Linux), chosen by the
// person with `p2p keys backend keychain|file`.
//
// With the keychain, keys.json keeps only the public part of the keys document (userId, did, the
// device certificate) and says where the secrets are (`store: "keychain"` and the item's service
// name). The secrets (the device signing seed `spk`, the agreement secret `kpk`, and on a key holder
// the identity seed `ik`) are one keychain item:
//
//   service  peer2peer-keys-<first 20 hex of SHA-256 of the home's real path>   (two homes never share one)
//   account  the device id (`did`): a new device (init, restore, a rotation) is a new item
//   secret   `p2p1.` + base64url(JSON {v, userId, did, spk, kpk, ik?})
//
// The home records the chosen backend in `<home>/keystore.json` (not secret), so where new keys are
// written is decided by that file, and where existing keys are read from by keys.json itself: a load
// never guesses. A keys document that says "keychain" is read from the keychain or not at all: when
// the keychain can't be read (locked, its tool missing, the item gone) the command stops with a
// clear error. Nothing ever makes new keys in their place.
//
// The OS tools do the work (no native module: the CLI is a single bundled file), each called by its
// absolute path, never through a shell or PATH (a planted `secret-tool` earlier in PATH would be
// handed the secret). A secret is never in a command line (other processes can read those): it goes
// over the tool's stdin, and it never appears in an error or a log line. What this does and doesn't
// protect against is in docs/security/threat-model.md ("Keys in the OS keychain").

import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { open, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { b64uDecode, deviceKeysV3FromSecrets, identityKeyFromSeed } from "@peer2peer/core/v3";
import { CliError } from "./errors.js";

export type KeyBackend = "file" | "keychain";

/** One run of an OS tool: what came back. `error` is the spawn's own failure (ENOENT, ETIMEDOUT). */
export interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: string;
}

/** Runs `file` with `args` (never through a shell), `input` on its stdin. Tests stand in their own. */
export type Runner = (file: string, args: readonly string[], input: string) => RunResult;

/** How long one keychain call may take: a locked keychain may be showing its unlock prompt. */
export const KEYCHAIN_TIMEOUT_MS = 20_000;

export const realRunner: Runner = (file, args, input) => {
  const r = spawnSync(file, [...args], {
    input,
    encoding: "utf8",
    timeout: KEYCHAIN_TIMEOUT_MS,
    windowsHide: true,
    shell: false,
    maxBuffer: 1 << 20,
    stdio: ["pipe", "pipe", "pipe"],
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", ...(r.error ? { error: (r.error as NodeJS.ErrnoException).code ?? "error" } : {}) };
};

/** A keychain call that failed: `reason` is safe to show (never the secret, never the tool's raw output with it). */
export class KeychainError extends Error {
  constructor(readonly reason: string) {
    super(reason);
  }
}

export interface Keychain {
  readonly kind: "macos" | "linux" | "windows";
  /** "the macOS Keychain", for messages. */
  readonly label: string;
  /** Why this keychain can't be used here (its tool is missing), or undefined. */
  unavailable(): string | undefined;
  /** The secret, or undefined when there is no such item. Throws KeychainError when the keychain can't be read. */
  get(service: string, account: string): string | undefined;
  /** Stores (or replaces) the item. Throws KeychainError. */
  set(service: string, account: string, label: string, secret: string): void;
  /** Deletes the item; false when there was none. Throws KeychainError. */
  remove(service: string, account: string): boolean;
}

/** Service names, accounts and labels go into command lines and the tools' own parsers: a narrow alphabet. */
const SAFE_ARG = /^[A-Za-z0-9_.-]{1,128}$/;
/** Secrets are `p2p1.` + base64url: never an option (no leading `-`), nothing a parser splits. */
const SAFE_SECRET = /^p2p1\.[A-Za-z0-9_-]{1,4096}$/;

function checkArgs(...args: string[]): void {
  for (const a of args) if (!SAFE_ARG.test(a)) throw new KeychainError("an item name with characters the keychain tools can't be given safely");
}

/**
 * The tool's message, safe to show: one line, short, with the secret (and anything shaped like one)
 * taken out. The tools don't echo secrets, but this never relies on it.
 */
export function toolMessage(out: string, secret?: string): string {
  let s = out;
  if (secret) s = s.split(secret).join("[secret]");
  s = s.replace(/p2p1\.[A-Za-z0-9_-]*/g, "[secret]").replace(/[A-Za-z0-9_-]{40,}/g, "[…]");
  s = s.replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return s.length > 160 ? `${s.slice(0, 160)}…` : s;
}

function spawnProblem(r: RunResult, tool: string): string | undefined {
  if (!r.error) return undefined;
  if (r.error === "ETIMEDOUT") return `${tool} didn't answer in ${KEYCHAIN_TIMEOUT_MS / 1000}s (is the keychain locked, with its unlock prompt waiting?)`;
  if (r.error === "ENOENT") return `${tool} isn't installed`;
  return `${tool} couldn't be run (${r.error})`;
}

// ---------------------------------------------------------------------------
// macOS: /usr/bin/security

export const SECURITY = "/usr/bin/security";

/**
 * The macOS Keychain through `/usr/bin/security`. Writes go through `security -i`, which reads its
 * commands from stdin, so the secret is never in a command line. The item's access list trusts
 * `/usr/bin/security` only (`-T`): other apps get the system's prompt. `keychainFile` points at
 * another keychain than the default one (the opt-in test uses a throwaway keychain).
 */
export function macosKeychain(run: Runner = realRunner, opts: { keychainFile?: string; exists?: (p: string) => boolean } = {}): Keychain {
  const kc = opts.keychainFile ? [opts.keychainFile] : [];
  const exists = opts.exists ?? existsSync;
  if (opts.keychainFile && /["\s\\]/.test(opts.keychainFile)) throw new KeychainError("a keychain path with spaces, quotes or backslashes");
  return {
    kind: "macos",
    label: "the macOS Keychain",
    unavailable: () => (exists(SECURITY) ? undefined : `${SECURITY} isn't there`),
    get(service, account) {
      checkArgs(service, account);
      const r = run(SECURITY, ["find-generic-password", "-s", service, "-a", account, "-w", ...kc], "");
      const p = spawnProblem(r, "security");
      if (p) throw new KeychainError(p);
      // 44: errSecItemNotFound.
      if (r.status === 44) return undefined;
      if (r.status !== 0) throw new KeychainError(`security couldn't read the item (exit ${r.status}${r.stderr.trim() ? `: ${toolMessage(r.stderr)}` : ""}): is the keychain locked?`);
      return r.stdout.replace(/\r?\n$/, "");
    },
    set(service, account, label, secret) {
      checkArgs(service, account, label);
      if (!SAFE_SECRET.test(secret)) throw new KeychainError("a secret in an unexpected form");
      // A new item only (no -U: changing an existing item's access list asks the user in a dialog, so
      // the caller deletes an item it replaces first). -T sets the access list to the security tool alone.
      const line = ["add-generic-password", "-s", service, "-a", account, "-l", label, "-T", SECURITY, "-w", secret, ...kc].join(" ");
      const r = run(SECURITY, ["-i"], `${line}\n`);
      const p = spawnProblem(r, "security");
      if (p) throw new KeychainError(p);
      // `security -i` exits 0 even when a command failed: whatever it said on stderr is a failure.
      if (r.status !== 0 || r.stderr.trim() !== "") throw new KeychainError(`security couldn't store the item${r.stderr.trim() ? ` (${toolMessage(r.stderr, secret)})` : ` (exit ${r.status})`}`);
    },
    remove(service, account) {
      checkArgs(service, account);
      const r = run(SECURITY, ["delete-generic-password", "-s", service, "-a", account, ...kc], "");
      const p = spawnProblem(r, "security");
      if (p) throw new KeychainError(p);
      if (r.status === 44) return false;
      if (r.status !== 0) throw new KeychainError(`security couldn't delete the item (exit ${r.status}${r.stderr.trim() ? `: ${toolMessage(r.stderr)}` : ""})`);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// Linux (and other Unixes with libsecret): secret-tool

/** Where secret-tool is looked for: system folders only (never PATH, never a user-writable folder). */
export const SECRET_TOOL_PATHS = ["/usr/bin/secret-tool", "/bin/secret-tool", "/run/current-system/sw/bin/secret-tool"];

/** The Secret Service (GNOME Keyring, KWallet) through libsecret's `secret-tool`; `store` reads the secret from stdin. */
export function libsecretKeychain(run: Runner = realRunner, opts: { exists?: (p: string) => boolean } = {}): Keychain {
  const exists = opts.exists ?? existsSync;
  const tool = () => SECRET_TOOL_PATHS.find((p) => exists(p));
  const need = () => {
    const t = tool();
    if (!t) throw new KeychainError("secret-tool isn't installed (the libsecret tools package: libsecret-tools on Debian and Ubuntu, libsecret on Fedora and Arch)");
    return t;
  };
  return {
    kind: "linux",
    label: "the Secret Service keyring (libsecret)",
    unavailable: () => (tool() ? undefined : "secret-tool isn't installed (the libsecret tools package)"),
    get(service, account) {
      checkArgs(service, account);
      const r = run(need(), ["lookup", "service", service, "account", account], "");
      const p = spawnProblem(r, "secret-tool");
      if (p) throw new KeychainError(p);
      if (r.status === 0) return r.stdout.replace(/\r?\n$/, "");
      // Not found: exit 1 and nothing said. Anything said is the service failing (no D-Bus session, locked).
      if (r.status === 1 && r.stderr.trim() === "" && r.stdout === "") return undefined;
      throw new KeychainError(`secret-tool couldn't read the item (exit ${r.status}${r.stderr.trim() ? `: ${toolMessage(r.stderr)}` : ""}): is a Secret Service (GNOME Keyring, KWallet) running and unlocked in this session?`);
    },
    set(service, account, label, secret) {
      checkArgs(service, account, label);
      if (!SAFE_SECRET.test(secret)) throw new KeychainError("a secret in an unexpected form");
      const r = run(need(), ["store", `--label=${label}`, "service", service, "account", account], secret);
      const p = spawnProblem(r, "secret-tool");
      if (p) throw new KeychainError(p);
      if (r.status !== 0) throw new KeychainError(`secret-tool couldn't store the item (exit ${r.status}${r.stderr.trim() ? `: ${toolMessage(r.stderr, secret)}` : ""})`);
    },
    remove(service, account) {
      checkArgs(service, account);
      // `clear` says nothing either way: looked up first, to tell whether there was one.
      const had = this.get(service, account) !== undefined;
      const r = run(need(), ["clear", "service", service, "account", account], "");
      const p = spawnProblem(r, "secret-tool");
      if (p) throw new KeychainError(p);
      if (r.status !== 0 && had) throw new KeychainError(`secret-tool couldn't delete the item (exit ${r.status}${r.stderr.trim() ? `: ${toolMessage(r.stderr)}` : ""})`);
      return had;
    },
  };
}

// ---------------------------------------------------------------------------
// Windows: Credential Manager (CredWriteW / CredReadW / CredDeleteW) through Windows PowerShell

/**
 * The script PowerShell runs (passed as -EncodedCommand: no secret in it). The request, the secret
 * included, comes as one JSON line on stdin. Credentials are generic ones persisted on this machine
 * only (CRED_PERSIST_LOCAL_MACHINE: never roamed to other machines). Exit 3: no such credential.
 */
export const WINDOWS_SCRIPT = String.raw`$ErrorActionPreference = 'Stop'
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P2PCred {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public int CredentialBlobSize; public IntPtr CredentialBlob; public int Persist;
    public int AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName;
  }
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredWriteW(ref CREDENTIAL c, int flags);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredReadW(string target, int type, int flags, out IntPtr c);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CredDeleteW(string target, int type, int flags);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static int Write(string target, string user, string label, string secret) {
    byte[] b = Encoding.UTF8.GetBytes(secret);
    IntPtr p = Marshal.AllocHGlobal(b.Length);
    try {
      Marshal.Copy(b, 0, p, b.Length);
      CREDENTIAL c = new CREDENTIAL();
      c.Type = 1; c.TargetName = target; c.UserName = user; c.Comment = label;
      c.CredentialBlobSize = b.Length; c.CredentialBlob = p; c.Persist = 2;
      if (!CredWriteW(ref c, 0)) return Marshal.GetLastWin32Error();
      return 0;
    } finally {
      for (int i = 0; i < b.Length; i++) Marshal.WriteByte(p, i, 0);
      Marshal.FreeHGlobal(p);
      Array.Clear(b, 0, b.Length);
    }
  }
  public static string Read(string target, out int err) {
    IntPtr p;
    err = 0;
    if (!CredReadW(target, 1, 0, out p)) { err = Marshal.GetLastWin32Error(); return null; }
    try {
      CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL));
      byte[] b = new byte[c.CredentialBlobSize];
      Marshal.Copy(c.CredentialBlob, b, 0, c.CredentialBlobSize);
      return Encoding.UTF8.GetString(b);
    } finally { CredFree(p); }
  }
  public static int Delete(string target) {
    if (!CredDeleteW(target, 1, 0)) return Marshal.GetLastWin32Error();
    return 0;
  }
}
'@
$target = [string]$req.target
if ($req.op -eq 'set') {
  $e = [P2PCred]::Write($target, [string]$req.account, [string]$req.label, [string]$req.secret)
  if ($e -ne 0) { [Console]::Error.WriteLine("CredWrite failed: Win32 error $e"); exit 2 }
  exit 0
}
if ($req.op -eq 'get') {
  $e = 0
  $s = [P2PCred]::Read($target, [ref]$e)
  if ($e -eq 1168) { exit 3 }
  if ($e -ne 0) { [Console]::Error.WriteLine("CredRead failed: Win32 error $e"); exit 2 }
  [Console]::Out.Write($s)
  exit 0
}
if ($req.op -eq 'delete') {
  $e = [P2PCred]::Delete($target)
  if ($e -eq 1168) { exit 3 }
  if ($e -ne 0) { [Console]::Error.WriteLine("CredDelete failed: Win32 error $e"); exit 2 }
  exit 0
}
exit 4
`;

/** Windows PowerShell 5.1, which every supported Windows has, by its absolute path. */
export function powershellPath(env: Record<string, string | undefined> = process.env): string {
  const root = env.SystemRoot ?? env.windir ?? "";
  const base = /^[A-Za-z]:\\[^"<>|?*\r\n]*$/.test(root) ? root.replace(/\\+$/, "") : "C:\\Windows";
  return `${base}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
}

export function windowsKeychain(run: Runner = realRunner, opts: { exists?: (p: string) => boolean; env?: Record<string, string | undefined> } = {}): Keychain {
  const exe = powershellPath(opts.env);
  const exists = opts.exists ?? existsSync;
  const encoded = Buffer.from(WINDOWS_SCRIPT, "utf16le").toString("base64");
  const call = (req: Record<string, string>, secret?: string) => {
    const r = run(exe, ["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded], `${JSON.stringify(req)}\n`);
    const p = spawnProblem(r, "PowerShell");
    if (p) throw new KeychainError(p);
    return { ...r, stderr: toolMessage(r.stderr, secret) };
  };
  const target = (service: string, account: string) => `${service}/${account}`;
  return {
    kind: "windows",
    label: "the Windows Credential Manager",
    unavailable: () => (exists(exe) ? undefined : `${exe} isn't there`),
    get(service, account) {
      checkArgs(service, account);
      const r = call({ op: "get", target: target(service, account) });
      if (r.status === 3) return undefined;
      if (r.status !== 0) throw new KeychainError(`the Credential Manager couldn't be read (exit ${r.status}${r.stderr ? `: ${r.stderr}` : ""})`);
      return r.stdout.replace(/\r?\n$/, "");
    },
    set(service, account, label, secret) {
      checkArgs(service, account, label);
      if (!SAFE_SECRET.test(secret)) throw new KeychainError("a secret in an unexpected form");
      const r = call({ op: "set", target: target(service, account), account, label, secret }, secret);
      if (r.status !== 0) throw new KeychainError(`the Credential Manager couldn't store the item (exit ${r.status}${r.stderr ? `: ${r.stderr}` : ""})`);
    },
    remove(service, account) {
      checkArgs(service, account);
      const r = call({ op: "delete", target: target(service, account) });
      if (r.status === 3) return false;
      if (r.status !== 0) throw new KeychainError(`the Credential Manager couldn't delete the item (exit ${r.status}${r.stderr ? `: ${r.stderr}` : ""})`);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// The keychain of this platform (tests stand one in)

let override: Keychain | null | undefined;

/** Tests: use `k` instead of the platform's keychain (null: none on this platform); undefined restores it. */
export function useKeychainForTests(k: Keychain | null | undefined): void {
  override = k;
  cache.clear();
}

/** This platform's keychain, or undefined where p2p knows none. */
export function platformKeychain(platform: NodeJS.Platform = process.platform): Keychain | undefined {
  if (override !== undefined) return override ?? undefined;
  if (platform === "darwin") return macosKeychain();
  if (platform === "win32") return windowsKeychain();
  if (platform === "linux" || platform === "freebsd" || platform === "openbsd") return libsecretKeychain();
  return undefined;
}

// ---------------------------------------------------------------------------
// The home's choice and the item's name

export const SERVICE_PREFIX = "peer2peer-keys-";
const LABEL = "Peer2Peer-device-keys";

/** The home as the keychain item names it: its real path when it exists (a symlinked P2P_HOME is the same home). */
export function canonicalHome(home: string): string {
  try {
    return realpathSync.native(home);
  } catch {
    return resolve(home);
  }
}

/** The keychain service for `home`: one per home, so two homes (two identities on one machine) never share an item. */
export function serviceFor(home: string): string {
  return `${SERVICE_PREFIX}${createHash("sha256").update(canonicalHome(home)).digest("hex").slice(0, 20)}`;
}

export function markerFile(home: string): string {
  return join(home, "keystore.json");
}

interface Marker {
  v: 1;
  backend: KeyBackend;
  /** keychain: the service of the item, and the home it was made for (to name it when the home moved). */
  service?: string;
  home?: string;
  at?: number;
}

/** The backend new keys are written to: keystore.json's, else files. Throws when the file is there but unreadable (fail closed). */
export function configuredBackend(home: string): KeyBackend {
  let raw: string;
  try {
    raw = readFileSync(markerFile(home), "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "file";
    throw new CliError("keystore_unreadable", `${markerFile(home)} can't be read (${(e as NodeJS.ErrnoException).code ?? "error"}): it says where this device's keys go. Fix or remove it`);
  }
  let m: Partial<Marker>;
  try {
    m = JSON.parse(raw) as Partial<Marker>;
  } catch {
    throw new CliError("keystore_unreadable", `${markerFile(home)} isn't valid JSON: it says where this device's keys go. Set it again: \`p2p keys backend keychain\` or \`p2p keys backend file\``);
  }
  if (m.backend === "file" || m.backend === "keychain") return m.backend;
  throw new CliError("keystore_unreadable", `${markerFile(home)} names no backend p2p knows: set it again with \`p2p keys backend keychain\` or \`p2p keys backend file\``);
}

function writeMarker(home: string, backend: KeyBackend): void {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  const m: Marker = { v: 1, backend, ...(backend === "keychain" ? { service: serviceFor(home), home: canonicalHome(home) } : {}), at: Date.now() };
  const f = markerFile(home);
  const tmp = `${f}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    writeFileSync(tmp, JSON.stringify(m, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    renameSync(tmp, f);
  } catch (e) {
    rmSync(tmp, { force: true });
    throw e;
  }
}

// ---------------------------------------------------------------------------
// The keys document, split and joined

/** The keys document as the CLI uses it (state.ts KeysDoc), with secrets. */
interface FullKeys {
  v: 1;
  userId: string;
  did: string;
  spk: string;
  kpk: string;
  cert: string;
  ik?: string;
  [k: string]: unknown;
}

/** keys.json when the secrets are in the keychain. */
interface SealedKeys {
  v: 1;
  userId: string;
  did: string;
  cert: string;
  store: "keychain";
  service: string;
  [k: string]: unknown;
}

const SECRET_FIELDS = ["spk", "kpk", "ik"] as const;
const SEAL_FIELDS = ["store", "service"] as const;

const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

/** Whether a raw keys.json holds the secrets itself. */
export function holdsSecrets(raw: unknown): boolean {
  return isObj(raw) && typeof raw.spk === "string" && raw.spk !== "";
}

/** Whether a raw keys.json says its secrets are in the keychain. */
export function isSealed(raw: unknown): raw is SealedKeys {
  return isObj(raw) && raw.store === "keychain" && !holdsSecrets(raw);
}

function without<T extends Record<string, unknown>>(o: T, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) if (!keys.includes(k)) out[k] = v;
  return out;
}

function payloadOf(k: FullKeys): string {
  const body = { v: 1, userId: k.userId, did: k.did, spk: k.spk, kpk: k.kpk, ...(typeof k.ik === "string" ? { ik: k.ik } : {}) };
  return `p2p1.${Buffer.from(JSON.stringify(body), "utf8").toString("base64url")}`;
}

/** The secrets in an item, checked against the public part they belong to: the device id from the signing seed, the userId from the identity seed. */
function openPayload(secret: string, pub: SealedKeys, where: string): { spk: string; kpk: string; ik?: string } {
  const bad = (why: string) => new CliError("keychain_mismatch", `the keychain item for this device (${where}) ${why}: this device's keys can't be loaded. Nothing was changed, and no new keys were made`);
  if (!SAFE_SECRET.test(secret)) throw bad("isn't one p2p wrote");
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(Buffer.from(secret.slice(5), "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    throw bad("isn't one p2p wrote");
  }
  const { spk, kpk, ik } = body;
  if (typeof spk !== "string" || typeof kpk !== "string" || (ik !== undefined && typeof ik !== "string")) throw bad("isn't one p2p wrote");
  try {
    if (deviceKeysV3FromSecrets(pub.userId, b64uDecode(spk, 32), b64uDecode(kpk, 32)).did !== pub.did) throw bad("holds another device's keys");
    if (typeof ik === "string" && identityKeyFromSeed(b64uDecode(ik, 32)).userId !== pub.userId) throw bad("holds another identity's key");
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw bad("isn't one p2p wrote");
  }
  return { spk, kpk, ...(typeof ik === "string" ? { ik } : {}) };
}

/** Items read in this process, by service and device id (a device's secrets never change: a new device is a new item). */
const cache = new Map<string, string>();

function keychainOrThrow(): Keychain {
  const kc = platformKeychain();
  if (!kc) throw new CliError("keychain_unavailable", `this device's keys are kept in an OS keychain, and p2p knows none on ${process.platform}. Nothing was changed, and no new keys were made`);
  const why = kc.unavailable();
  if (why) throw new CliError("keychain_unavailable", `this device's keys are in ${kc.label}, which can't be used here: ${why}. Nothing was changed, and no new keys were made`);
  return kc;
}

/** The secrets of a sealed keys.json from the keychain, or a clear error (never a guess, never new keys). */
function unseal(home: string, raw: SealedKeys): FullKeys {
  const service = serviceFor(home);
  if (raw.service !== service) {
    throw new CliError(
      "keychain_moved",
      `this device's keys are in the keychain under another home's name (${String(raw.service).slice(0, 64)}, not ${service}): was ${home} moved or copied from elsewhere? Move it back, or run p2p with P2P_HOME set to the folder it was made in. Nothing was changed, and no new keys were made`,
    );
  }
  if (typeof raw.did !== "string" || typeof raw.userId !== "string") throw new CliError("keychain_mismatch", `${join(home, "cli", "keys.json")} is damaged: no device id. Nothing was changed`);
  const kc = keychainOrThrow();
  const key = `${service}|${raw.did}`;
  let secret = cache.get(key);
  if (secret === undefined) {
    try {
      secret = kc.get(service, raw.did);
    } catch (e) {
      const why = e instanceof KeychainError ? e.reason : "an unexpected error";
      throw new CliError("keychain_unreadable", `this device's keys are in ${kc.label} (item ${service}, account ${raw.did}), which couldn't be read: ${why}. Unlock it and run the command again. Nothing was changed, and no new keys were made`);
    }
    if (secret === undefined) {
      throw new CliError(
        "keychain_missing",
        `this device's keys should be in ${kc.label} (item ${service}, account ${raw.did}), and it has no such item: was it deleted, or is this another user account? Restore it from a keychain backup, or \`p2p backup restore\` on a fresh home. Nothing was changed, and no new keys were made`,
      );
    }
  }
  const secrets = openPayload(secret, raw, `${service}, account ${raw.did}`);
  cache.set(key, secret);
  return { ...(without(raw, SEAL_FIELDS) as Omit<FullKeys, "spk" | "kpk">), ...secrets } as FullKeys;
}

/** The keys document as the CLI uses it from what keys.json holds: the secrets from the keychain when it says so. */
export function openKeys(home: string, raw: unknown): unknown {
  if (raw === undefined || raw === null) return raw;
  if (isSealed(raw)) return unseal(home, raw);
  // The secrets are in the file (the default, or a move that hasn't finished): those are the keys.
  return isObj(raw) ? without(raw, SEAL_FIELDS) : raw;
}

/**
 * The device signing seed for the person token (projects.ts), read synchronously: from keys.json,
 * or from the keychain when keys.json says so. Undefined when it can't be read.
 */
export function signingSeedSync(home: string): string | undefined {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8"));
  } catch {
    return undefined;
  }
  try {
    const k = openKeys(home, raw);
    return isObj(k) && typeof k.spk === "string" && k.spk !== "" ? k.spk : undefined;
  } catch {
    return undefined;
  }
}

/** Throws the keychain's error when this home's keys are in a keychain that can't be read now; else nothing. */
export function assertKeysReadable(home: string): void {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8"));
  } catch {
    return;
  }
  if (isSealed(raw)) unseal(home, raw);
}

/** Whether this home's keys are in a keychain that can't be read now. */
export function keysUnreadable(home: string): boolean {
  try {
    assertKeysReadable(home);
    return false;
  } catch {
    return true;
  }
}

/** What CliState's backend is (state.ts CliBackend), restated here to keep this module free of state.ts. */
export interface DocStore {
  read(name: string): Promise<unknown>;
  write(name: string, value: unknown): Promise<void>;
  remove?(name: string): Promise<void>;
  withLock<T>(fn: () => Promise<T>): Promise<T>;
}

/**
 * Writes `doc` to keys.json, and when the file it replaces held secrets that are no longer in it,
 * overwrites that file's old bytes before they are gone (best effort: on an SSD or a copy-on-write
 * file system the old blocks may still be somewhere; the keychain is the place the keys are kept now).
 */
async function replaceKeysFile(inner: DocStore, home: string, doc: unknown): Promise<void> {
  const path = join(home, "cli", "keys.json");
  let fh;
  try {
    fh = await open(path, "r+");
  } catch {
    fh = undefined;
  }
  try {
    const before = fh ? await fh.stat() : undefined;
    await inner.write("keys", doc);
    if (fh && before && before.size > 0) {
      const now = await stat(path).catch(() => undefined);
      // Only the file the write replaced (renamed over): never the one just written.
      if (!now || now.ino !== before.ino || now.dev !== before.dev) {
        await fh.write(Buffer.alloc(before.size, 0), 0, before.size, 0);
        await fh.sync();
      }
    }
  } finally {
    await fh?.close().catch(() => {});
  }
}

/**
 * Stores `k`'s secrets in the keychain and reads them back; throws unless the item reads back byte
 * for byte. An item that already holds them is left as it is (a renewed certificate changes only
 * keys.json). One that holds something else is replaced only with `replace` (the keys are still in
 * keys.json, or are new); otherwise it may be the only copy of this device's keys, and it stays.
 */
function storeAndVerify(kc: Keychain, home: string, k: FullKeys, replace: boolean): void {
  const service = serviceFor(home);
  const secret = payloadOf(k);
  const key = `${service}|${k.did}`;
  if (cache.get(key) === secret) return;
  try {
    const have = kc.get(service, k.did);
    if (have === secret) {
      cache.set(key, secret);
      return;
    }
    if (have !== undefined) {
      if (!replace) throw new CliError("keychain_mismatch", `${kc.label} holds other keys for this device (item ${service}, account ${k.did}) than the ones being written: nothing was changed`);
      kc.remove(service, k.did);
      cache.delete(key);
    }
    kc.set(service, k.did, LABEL, secret);
  } catch (e) {
    if (e instanceof CliError) throw e;
    throw new CliError("keychain_write_failed", `couldn't store this device's keys in ${kc.label}: ${e instanceof KeychainError ? e.reason : "an unexpected error"}. Nothing was changed: the keys are where they were`);
  }
  let back: string | undefined;
  try {
    back = kc.get(service, k.did);
  } catch (e) {
    throw new CliError("keychain_write_failed", `stored this device's keys in ${kc.label}, but couldn't read them back: ${e instanceof KeychainError ? e.reason : "an unexpected error"}. Nothing was changed: the keys are where they were`);
  }
  if (back !== secret) throw new CliError("keychain_write_failed", `the keys read back from ${kc.label} weren't the ones stored. Nothing was changed: the keys are where they were`);
  cache.set(`${service}|${k.did}`, secret);
}

function sealedOf(home: string, k: FullKeys): SealedKeys {
  return { ...(without(k, [...SECRET_FIELDS, ...SEAL_FIELDS]) as Omit<SealedKeys, "store" | "service">), store: "keychain", service: serviceFor(home) } as SealedKeys;
}

function asFull(v: unknown): FullKeys {
  if (!isObj(v) || typeof v.spk !== "string" || typeof v.kpk !== "string" || typeof v.did !== "string" || typeof v.userId !== "string") {
    throw new CliError("internal", "a keys document without its keys");
  }
  return without(v, SEAL_FIELDS) as FullKeys;
}

/**
 * CliState's backend with the keys document routed: written to the keychain when the home chose it
 * (keystore.json), read from wherever keys.json says. Every other document passes through.
 */
export class KeyStoreBackend implements DocStore {
  constructor(
    readonly inner: DocStore,
    readonly home: string,
    /** A read-only run's overlay (readonly.ts): writes stay in memory, never reach the keychain. */
    private readonly opts: { memoryOnly?: boolean } = {},
  ) {}

  async read(name: string): Promise<unknown> {
    const raw = await this.inner.read(name);
    return name === "keys" ? openKeys(this.home, raw) : raw;
  }

  /** keys.json as it is on disk (sealed or not). */
  readRaw(): Promise<unknown> {
    return this.inner.read("keys");
  }

  async write(name: string, value: unknown): Promise<void> {
    if (name !== "keys" || value === null || value === undefined || this.opts.memoryOnly) return this.inner.write(name, value);
    const k = asFull(value);
    if (configuredBackend(this.home) === "keychain") {
      // Replacing an item is only for keys that aren't sealed already (then the item may be their only copy).
      storeAndVerify(keychainOrThrow(), this.home, k, !isSealed(await this.inner.read("keys")));
      return replaceKeysFile(this.inner, this.home, sealedOf(this.home, k));
    }
    return this.inner.write(name, k);
  }

  remove(name: string): Promise<void> {
    return this.inner.remove ? this.inner.remove(name) : this.inner.write(name, null);
  }

  withLock<T>(fn: () => Promise<T>): Promise<T> {
    return this.inner.withLock(fn);
  }
}

// ---------------------------------------------------------------------------
// Moving keys between the backends (`p2p keys backend`), and finishing a move

export interface KeyStoreStatus {
  /** Where new keys are written (keystore.json). */
  configured: KeyBackend;
  /** Where this device's keys are now: none (no identity here yet), file or keychain. */
  keys: "none" | "file" | "keychain";
  /** Whether they could be read just now. */
  readable: boolean;
  /** What is wrong, in words, when something is. */
  problem?: string;
  /** The OS keychain p2p uses on this platform. */
  keychain: { kind?: Keychain["kind"]; label: string; available: boolean; why?: string };
  /** keychain: the item's service name and account (not secret). */
  item?: { service: string; account: string };
}

/** Where this home's keys are and whether they can be read (no secret in it). Read only. */
export function keyStoreStatus(home: string): KeyStoreStatus {
  const kc = platformKeychain();
  const why = kc ? kc.unavailable() : `p2p knows no OS keychain on ${process.platform}`;
  const keychain = { ...(kc ? { kind: kc.kind } : {}), label: kc?.label ?? "an OS keychain", available: why === undefined, ...(why !== undefined ? { why } : {}) };
  let configured: KeyBackend = "file";
  let problem: string | undefined;
  try {
    configured = configuredBackend(home);
  } catch (e) {
    problem = (e as Error).message;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(home, "cli", "keys.json"), "utf8"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return { configured, keys: "none", readable: false, ...(problem ? { problem } : {}), keychain };
    return { configured, keys: "file", readable: false, problem: `${join(home, "cli", "keys.json")} can't be read`, keychain };
  }
  if (isSealed(raw)) {
    const item = { service: String(raw.service), account: String(raw.did) };
    try {
      unseal(home, raw);
      return { configured, keys: "keychain", readable: true, ...(problem ? { problem } : {}), keychain, item };
    } catch (e) {
      return { configured, keys: "keychain", readable: false, problem: (e as Error).message, keychain, item };
    }
  }
  if (!holdsSecrets(raw)) return { configured, keys: "file", readable: false, problem: `${join(home, "cli", "keys.json")} holds no keys`, keychain };
  if (configured === "keychain" && !problem) problem = `the keys are still in ${join(home, "cli", "keys.json")}: the move into the keychain hasn't finished (\`p2p keys backend keychain\` finishes it)`;
  return { configured, keys: "file", readable: true, ...(problem ? { problem } : {}), keychain };
}

export interface MoveResult {
  backend: KeyBackend;
  /** Whether keys were moved (false: there were none yet, or they were there already). */
  moved: boolean;
  /** Where new keys go from now on, in words. */
  where: string;
  item?: { service: string; account: string };
  warnings: string[];
}

/**
 * Moves this home's keys into the keychain: stored, read back and compared byte for byte, and only
 * then keys.json loses its secrets (its old bytes overwritten). Each step can be repeated: an
 * interrupted move is finished by running it again (or by the next command that loads the keys).
 */
export async function moveKeysToKeychain(store: KeyStoreBackend): Promise<MoveResult> {
  const home = store.home;
  const kc = platformKeychain();
  if (!kc) throw new CliError("keychain_unavailable", `p2p knows no OS keychain on ${process.platform}: the keys stay in files`);
  const why = kc.unavailable();
  if (why) throw new CliError("keychain_unavailable", `${kc.label} can't be used here: ${why}. Nothing was changed: the keys stay in files`);
  return store.withLock(async () => {
    const raw = await store.readRaw();
    const service = serviceFor(home);
    if (raw === undefined) {
      writeMarker(home, "keychain");
      return { backend: "keychain", moved: false, where: `${kc.label}: no keys here yet, the ones this device makes will be kept there`, warnings: [] };
    }
    if (isSealed(raw)) {
      unseal(home, raw);
      writeMarker(home, "keychain");
      return { backend: "keychain", moved: false, where: `${kc.label} (they were there already)`, item: { service, account: String(raw.did) }, warnings: [] };
    }
    const k = asFull(raw);
    storeAndVerify(kc, home, k, true);
    writeMarker(home, "keychain");
    await replaceKeysFile(store.inner, home, sealedOf(home, k));
    return { backend: "keychain", moved: true, where: kc.label, item: { service, account: k.did }, warnings: [] };
  });
}

/**
 * Moves this home's keys back into keys.json: written and read back first, then the keychain item
 * is deleted. Fails closed: keys that can't be read from the keychain stay there.
 */
export async function moveKeysToFiles(store: KeyStoreBackend): Promise<MoveResult> {
  const home = store.home;
  const where = `${join(home, "cli", "keys.json")} (0600)`;
  return store.withLock(async () => {
    const raw = await store.readRaw();
    const warnings: string[] = [];
    if (raw === undefined || !isSealed(raw)) {
      writeMarker(home, "file");
      return { backend: "file", moved: false, where: raw === undefined ? `${where}: no keys here yet` : `${where} (they were there already)`, warnings };
    }
    const k = unseal(home, raw);
    await store.inner.write("keys", k);
    const back = await store.inner.read("keys");
    if (!isObj(back) || payloadOf(asFull(back)) !== payloadOf(k)) {
      throw new CliError("keys_write_failed", `the keys read back from ${where} weren't the ones written: the keychain item was kept`);
    }
    writeMarker(home, "file");
    const kc = platformKeychain();
    const service = String(raw.service);
    try {
      kc?.remove(service, k.did);
      cache.delete(`${service}|${k.did}`);
    } catch (e) {
      warnings.push(`the keys are in ${where} now, but the keychain item ${service} (account ${k.did}) couldn't be deleted (${e instanceof KeychainError ? e.reason : "error"}): delete it yourself`);
    }
    return { backend: "file", moved: true, where, warnings };
  });
}

/**
 * A home that chose the keychain whose keys.json holds secrets (a move that was interrupted, or a
 * rotation or follow that swapped in a new identity's files): moves them now. Called on load by
 * commands that may write; never by read-only ones. Returns a warning when it couldn't.
 */
export async function finishPendingMove(store: KeyStoreBackend): Promise<string | undefined> {
  let backend: KeyBackend;
  try {
    backend = configuredBackend(store.home);
  } catch (e) {
    return (e as Error).message;
  }
  if (backend !== "keychain") return undefined;
  if (!holdsSecrets(await store.readRaw())) return undefined;
  try {
    await moveKeysToKeychain(store);
    return undefined;
  } catch (e) {
    return `this device's keys are still in ${join(store.home, "cli", "keys.json")}, not in the keychain this home chose: ${(e as Error).message}`;
  }
}

/** Best effort: deletes this home's keychain item for device `did` (a half-made identity that was wiped). */
export function forgetKeychainItem(home: string, did: string | undefined): void {
  if (!did) return;
  try {
    if (configuredBackend(home) !== "keychain") return;
    const service = serviceFor(home);
    platformKeychain()?.remove(service, did);
    cache.delete(`${service}|${did}`);
  } catch {
    // the item stays; nothing else depends on it
  }
}
