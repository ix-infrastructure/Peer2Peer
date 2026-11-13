// Copyright 2026 Ix Infrastructure Inc.
//
// The identity commands (docs/protocol.md §2): init, whoami, devices and
// revocation, device linking, the backup phrase, profiles and proofs.

import { chmod, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { resolveTxt } from "node:dns/promises";
import {
  addIdentityVersion,
  b64uEncode,
  backupPhraseFromSeed,
  canonicalProofLoc,
  createCap,
  createDeviceCert,
  createIdentityDoc,
  createLinkRequest,
  createMembershipStatement,
  createProof,
  daysPastExp,
  decodeTyped,
  displayAddress,
  displayFingerprint,
  displayProfile,
  dnsProofRecord,
  encodeLinkCode,
  generateDeviceKeysV3,
  generateIdentityKey,
  identityFreshness,
  identityKeyFromBackupPhrase,
  isValidName,
  jumpIdentity,
  liveFriendshipsV3,
  jwsHash,
  LINK_TTL_SEC,
  linkCompareCode,
  linkId,
  loadCircle,
  MAX_DEVICES,
  MAX_RELAYS,
  newLinkSecret,
  nowSec,
  nextMembershipN,
  openLinkResponse,
  P2PError,
  parseLinkCode,
  PROFILE_AVATAR_DATA_MAX,
  sanitizePeerText,
  sealLinkResponse,
  selectLinkRequest,
  TYP3,
  verifiedProofs,
  verifyDeviceCertV3,
  verifyMembershipStatement,
  verifyProofSignature,
  type DisplayProfile,
  type Profile,
  type ProofFetchers,
} from "@peer2peer/core/v3";
import { capPeek, certDid, defaultLabel, defaultName, joinCapOf, newKeysDoc, type App } from "./app.js";
import { defaultRelays, normalizeRelays } from "./config.js";
import { CliError } from "./errors.js";
import { isOwnRelay, isPrivateRelayHost, PRIVATE_RESOLVE_MARK, privateGuardLookup, privateRelayMessage } from "./shortcode.js";
import { fetchTips, linkGet, linkPut, openLinkConnection, relayCode, sleep } from "./relay-client.js";
import type { SelfDoc } from "./state.js";
import { exportAll, sendSync, verifiedIssuedCap } from "./sync.js";
import { receiving } from "./inbound.js";
import { recordJoin, resignJoin } from "./circle-ops.js";
import { setupIx, type SetupIx } from "./ix-local.js";
import { renewPersonToken } from "./projects.js";

// ---------------------------------------------------------------------------
// init

export interface InitResult {
  userId: string;
  address: string;
  fingerprint: string;
  did: string;
  relays: string[];
  published: string[];
  failed: { relay: string; code: string }[];
}

/** The `p2p` command as the person types it here (Windows PowerShell blocks npm's p2p.ps1 shim; p2p.cmd works everywhere on Windows). */
export function p2pCommand(platform: NodeJS.Platform = process.platform): string {
  return platform === "win32" ? "p2p.cmd" : "p2p";
}

/**
 * Why a new identity can't be made here (no relay anywhere), naming the three ways in. There is
 * no default relay, by design (bring your own relay).
 */
export function noRelaysReason(home: string, platform: NodeJS.Platform = process.platform): string {
  const p = p2pCommand(platform);
  return (
    `no relays configured. Already use Peer2Peer on another device? Run \`p2p link start\` there, then \`${p} link join <code>\` here (one identity, not a second one). ` +
    `Have an invite? \`${p} join <invite link or code>\`. ` +
    `Starting a new identity? Pass --relay wss://… (1–5, your group's relay), or set P2P_DEFAULT_RELAYS, or "defaultRelays" in ${home}/config.json`
  );
}

export async function init(app: App, opts: { name?: string; relays?: string[] }): Promise<InitResult> {
  if (await app.load(false)) throw new CliError("already_initialized", `${app.home} already holds an identity (${app.userId})`);
  const relays = opts.relays && opts.relays.length > 0 ? normalizeRelays(opts.relays) : defaultRelays(app.env, app.file);
  if (relays.length === 0) throw new CliError("no_relays", noRelaysReason(app.home));
  const name = opts.name ?? defaultName();
  if (!isValidName(name)) throw new CliError("usage", "--name must match [a-z0-9._-]{1,32}");
  const ik = generateIdentityKey();
  const device = generateDeviceKeysV3(ik.userId);
  const cert = createDeviceCert(ik, { signingPublicKey: device.signingPublicKey, agreementPublicKey: device.agreementPublicKey, label: defaultLabel() });
  const doc = createIdentityDoc(ik, { ver: 1, prev: null, name, relays, devices: [device.did], keyholders: [device.did], by: device.did, certs: [cert] });
  const keys = newKeysDoc(ik.userId, device, cert, ik);
  const self: SelfDoc = { name, relays, createdAt: Date.now() };
  // A person.key from before this identity existed no longer counts (projects.ts renewPersonToken).
  // Replaced before any key is written: if that fails, no identity is made here.
  renewPersonToken(app.home);
  await app.state.put("keys", keys);
  await app.state.put("self", self);
  app.setKeys(keys, self);
  await addIdentityVersion(app.store, doc);
  await app.store.putDeviceCert({ userId: ik.userId, did: device.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
  await app.store.recordPublished({ hash: jwsHash(doc), devices: [device.did], relays });
  // Not before the first document is on the relays (refreshDeviceInfo builds on the relays' head).
  app.deviceInfoDeferred = true;
  await app.connect({ allowNone: true });
  const r = await app.publishDoc(doc, relays);
  app.deviceInfoDeferred = false;
  if (r.ok.length > 0) await app.refreshDeviceInfo().catch(() => undefined);
  return { userId: ik.userId, address: displayAddress(ik.userId, name), fingerprint: displayFingerprint(ik.userId), did: device.did, relays, published: r.ok, failed: r.failed };
}


// ---------------------------------------------------------------------------
// setup: a friendlier, idempotent init (P4)

export interface SetupResult {
  userId: string;
  address: string;
  fingerprint: string;
  did: string;
  relays: string[];
  /** False when this home already held an identity (nothing was changed). */
  created: boolean;
  published?: string[];
  failed?: { relay: string; code: string }[];
  /** Present only when the phrase was saved (`file`) or printing was asked for (`phrase`). */
  backup?: { file?: string; phrase?: string };
  /** Ix, optional and recommended (ix-local.ts setupIx): found, enabled, recommended (with the command for the person to run), and what to do when it isn't on. Never installed for them. */
  ix?: SetupIx;
  /** This device is the only key holder and the backup phrase was never shown or saved (`p2p backup show`). */
  backupNeeded?: true;
}

export const BACKUP_FILE_NAME = "backup-phrase.txt";

export type BackupMode = "file" | "print" | "none";

export async function setup(
  app: App,
  opts: {
    name?: string;
    relays?: string[];
    backup?: BackupMode;
    backupFile?: string;
    ix?: boolean;
    /** Asked only once an identity was created here (never before its key exists), when `backup` isn't given. */
    chooseBackup?: (created: InitResult) => Promise<BackupMode>;
  },
): Promise<SetupResult> {
  let created = false;
  let pub: { published: string[]; failed: { relay: string; code: string }[] } | undefined;
  let backupMode = opts.backup;
  if (!(await app.load(false))) {
    const r = await init(app, { name: opts.name, relays: opts.relays });
    created = true;
    pub = { published: r.published, failed: r.failed };
    if (backupMode === undefined && opts.chooseBackup) backupMode = await opts.chooseBackup(r);
  }
  const v = await app.ownView();
  const out: SetupResult = {
    userId: app.userId,
    address: displayAddress(app.userId, v.head.name),
    fingerprint: displayFingerprint(app.userId),
    did: app.did,
    relays: v.head.relays,
    created,
    ...(pub ?? {}),
  };
  try {
    out.ix = await setupIx(app, created, { reoffer: opts.ix === true });
  } catch (e) {
    // Never fails a setup: Ix is optional.
    out.ix = { found: false, installed: false, recommended: false, enabled: false, hint: `couldn't check for Ix: ${sanitizePeerText((e as Error).message, 200)}` };
  }
  if (backupMode === "file") {
    const path = opts.backupFile ?? join(app.home, BACKUP_FILE_NAME);
    const { phrase } = await backupShow(app);
    try {
      // Never overwrite: an existing file may be the only copy of another phrase.
      await writeFile(path, `${phrase}\n`, { mode: 0o600, flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliError("exists", `${path} already exists: not overwriting it (pass --backup-file <path>)`, { ...out });
      throw e;
    }
    await chmod(path, 0o600);
    out.backup = { file: path };
  } else if (backupMode === "print") {
    out.backup = { phrase: (await backupShow(app)).phrase };
  }
  // This device is the only key holder and its phrase was never shown: losing it loses the identity.
  if (!out.backup && app.isKeyholder && v.head.keyholders.length < 2 && !app.self?.backupShown) out.backupNeeded = true;
  return out;
}

// ---------------------------------------------------------------------------
// relays (the list in your identity document, §5.8)

export async function relaysList(app: App): Promise<{ relays: string[] }> {
  return { relays: [...(await app.ownView()).head.relays] };
}

export interface RelaysChange {
  relays: string[];
  ver: number;
  published: string[];
  failed: { relay: string; code: string }[];
  /** Friends sent a fresh friend cap naming the new relay list. */
  capsReissued: number;
  /** Circles whose join statement was re-signed with a co-member cap on the new relays. */
  rejoined: string[];
  /** relays remove: old caps revoked at the removed relay (best effort). */
  revokedAtRemoved?: number;
}

async function changeRelays(app: App, f: (cur: string[]) => string[]): Promise<RelaysChange> {
  app.requireKeyholder("Changing your relays");
  await app.connectAndDrain();
  const pub = await app.publishNext((p) => {
    p.relays = f(p.relays);
  });
  const re = await reissueForRelays(app);
  return { relays: [...(await app.ownView()).head.relays], ver: pub.ver, published: pub.ok, failed: pub.failed, ...re };
}

/**
 * review L5: caps name the relays they admit at. After the relay list changes,
 * friends get a fresh friend cap on the new list and our circle joins are
 * re-signed with a fresh co-member cap, so nobody is left holding caps only
 * for relays we dropped. Old caps aren't revoked: a friend who hasn't picked
 * up the new one still reaches the relays both name.
 */
export async function reissueForRelays(app: App): Promise<{ capsReissued: number; rejoined: string[] }> {
  const cur = new Set(app.relays);
  const sameRelays = (rs: readonly string[]) => rs.length === cur.size && rs.every((r) => cur.has(r));
  const live = new Set((await liveFriendshipsV3(app.store, app.signerCtx())).map((x) => (x.inviter === app.userId ? x.invitee : x.inviter)));
  const now = nowSec();
  const stale = new Set<string>();
  const current = new Set<string>();
  for (const c of await app.store.listCapsIssued()) {
    const facts = verifiedIssuedCap(app, c.jws);
    if (!facts || facts.iss !== app.userId || facts.sub === "*" || facts.sub === app.userId || facts.kinds[0] !== "*" || facts.exp <= now) continue;
    if (!live.has(facts.sub)) continue;
    (sameRelays(facts.relays) ? current : stale).add(facts.sub);
  }
  let capsReissued = 0;
  const issued = [];
  for (const sub of stale) {
    if (current.has(sub)) continue;
    const cap = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub, relays: app.relays });
    issued.push(await app.recordIssued(cap));
    try {
      const d = await app.deliver(sub, "contact", { own: app.userId, sid: "~contact" }, { text: cap });
      if (d.relays.length > 0) capsReissued++;
    } catch (e) {
      app.warn(`couldn't send ${await app.addressOf(sub)} your new relays: ${(e as Error).message}`);
    }
  }
  const rejoined: string[] = [];
  for (const rec of await app.store.listCircles()) {
    const mine = rec.statements[app.userId];
    if (!rec.joinedByMe || mine?.op !== "join") continue;
    const cap = joinCapOf(mine.jws);
    const p = cap ? capPeek(cap) : undefined;
    if (p && sameRelays(p.relays)) continue;
    if (await resignJoin(app, rec.cid)) rejoined.push(rec.cid);
  }
  if (issued.length > 0) await sendSync(app, { capsIssued: issued });
  return { capsReissued, rejoined };
}

/** Adds a relay to your identity document (the next version, published to old and new relays). */
export async function relaysAdd(app: App, url: string): Promise<RelaysChange> {
  const r = normalizeRelays([url])[0];
  const cur = (await app.ownView()).head.relays;
  if (cur.includes(r)) return { relays: [...cur], ver: (await app.ownView()).head.ver, published: [], failed: [], capsReissued: 0, rejoined: [] };
  if (cur.length >= MAX_RELAYS) throw new CliError("bad_relay", `at most ${MAX_RELAYS} relays: remove one first`);
  return changeRelays(app, (list) => [...list.filter((x) => x !== r), r]);
}

/** Removes a relay (at least one must stay). The removed relay gets the new version too, so it stops admitting removed state. */
export async function relaysRemove(app: App, url: string): Promise<RelaysChange> {
  const r = normalizeRelays([url])[0];
  const cur = (await app.ownView()).head.relays;
  if (!cur.includes(r)) throw new CliError("not_found", `${r} is not one of your relays`);
  if (cur.length === 1) throw new CliError("usage", "that is your only relay: add another first");
  // Caps naming the dropped relay, captured before the re-issue adds new ones.
  const old = (await app.store.listCapsIssued()).filter((c) => c.iss === app.userId && c.relays.includes(r));
  const out = await changeRelays(app, (list) => list.filter((x) => x !== r));
  // review L2: revoke them at the dropped relay only (our devices are still in its allowlist). Other
  // relays keep honouring them, so friends who haven't picked up the new caps stay covered.
  // Best effort: the relay may be down.
  let revokedAtRemoved = 0;
  const pool = app.pool ?? (await app.connect({ allowNone: true }));
  for (const c of old) {
    if ((await pool.revoke(c.capid, [r]).catch(() => [] as string[])).length > 0) revokedAtRemoved++;
  }
  if (revokedAtRemoved < old.length) app.warn(`couldn't revoke ${old.length - revokedAtRemoved} of your old caps at ${r}; they expire on their own`);
  return { ...out, revokedAtRemoved };
}

// ---------------------------------------------------------------------------
// whoami / devices

export interface DeviceRow {
  did: string;
  label: string;
  keyholder: boolean;
  thisDevice: boolean;
  certExp?: number;
}

export interface WhoamiResult {
  userId: string;
  name: string;
  address: string;
  fingerprint: string;
  did: string;
  keyholder: boolean;
  devices: DeviceRow[];
  relays: string[];
  doc: { ver: number; exp: number; freshness: string; daysPastExp: number; forked: boolean; historyGap: boolean };
  profile: DisplayProfile;
  proofs: number;
  defaultCircle?: string;
  warnings: string[];
}

export async function devices(app: App): Promise<DeviceRow[]> {
  const v = await app.ownView();
  const rows: DeviceRow[] = [];
  for (const d of v.devices) {
    const c = v.head.certs?.find((x) => certDid(x) === d) ?? (d === app.did ? app.keys!.cert : undefined);
    let label = "";
    let certExp: number | undefined;
    if (c) {
      const p = decodeTyped(c, TYP3.device).payload;
      label = sanitizePeerText(p.label, 64);
      certExp = typeof p.exp === "number" ? p.exp : undefined;
    }
    rows.push({ did: d, label, keyholder: v.keyholders.includes(d), thisDevice: d === app.did, ...(certExp ? { certExp } : {}) });
  }
  return rows;
}

export async function whoami(app: App): Promise<WhoamiResult> {
  const v = await app.ownView();
  const warnings: string[] = [];
  const f = identityFreshness(v.head.exp);
  if (f !== "fresh") warnings.push(`your identity document expired ${daysPastExp(v.head.exp)} days ago: run any command on a key-holding device to re-publish`);
  if (app.isKeyholder && v.keyholders.length < 2 && !app.self?.backupShown) {
    warnings.push("only this device holds your identity key and you haven't saved a backup: run `p2p backup show`, or link a second key holder (`p2p link start --keyholder`)");
  }
  if (app.self?.unpublished?.length) warnings.push(`your document isn't on ${app.self.unpublished.join(", ")} yet`);
  return {
    userId: app.userId,
    name: v.head.name,
    address: displayAddress(app.userId, v.head.name),
    fingerprint: displayFingerprint(app.userId),
    did: app.did,
    keyholder: app.isKeyholder,
    devices: await devices(app),
    relays: v.head.relays,
    doc: { ver: v.head.ver, exp: v.head.exp, freshness: f, daysPastExp: daysPastExp(v.head.exp), forked: v.forked, historyGap: v.historyGap },
    profile: displayProfile(v.head.profile),
    proofs: v.head.proofs?.length ?? 0,
    ...(app.self?.defaultCircle ? { defaultCircle: app.self.defaultCircle } : {}),
    warnings,
  };
}

/**
 * Revokes a device (§2.5): the next document version without it. Caps that
 * device signed stop working at relays (§5.3 L1), so they are revoked and
 * re-issued from this device, and membership statements it signed are
 * re-signed (§3.3 N4).
 */
export async function revokeDevice(app: App, did: string): Promise<{ revoked: string; ver: number; capsReissued: number; rejoined: string[]; warnings: string[] }> {
  app.requireKeyholder("Revoking a device");
  if (did === app.did) throw new CliError("usage", "a device can't revoke itself; revoke it from another key-holding device");
  await app.connectAndDrain();
  // Another key holder may have linked devices since: build on the relays' head (also review H2).
  await app.refreshIdentity(app.userId, app.relays, { force: true, strict: true });
  const v = await app.ownView();
  if (!v.devices.includes(did)) throw new CliError("not_found", `${did} is not one of your devices`);
  const wasKeyholder = v.keyholders.includes(did);
  const pub = await app.publishNext((p) => {
    p.devices = p.devices.filter((d) => d !== did);
    p.keyholders = p.keyholders.filter((d) => d !== did);
    p.certs = (p.certs ?? []).filter((c) => certDid(c) !== did);
  });
  // Caps the revoked device signed.
  const signedBy = (jws: string) => {
    try {
      const cert = decodeTyped(jws, TYP3.cap).payload.cert;
      return typeof cert === "string" && certDid(cert) === did;
    } catch {
      return false;
    }
  };
  const old = await app.store.takeCapsIssued((c) => signedBy(c.jws));
  await app.revokeCaps(old);
  let reissued = 0;
  // review M5: what a cap grants comes from its signed JWS, never the stored record's fields,
  // and replacements go only to live friends.
  const live = new Set((await liveFriendshipsV3(app.store, app.signerCtx())).map((f) => (f.inviter === app.userId ? f.invitee : f.inviter)));
  const subs = new Set<string>();
  for (const c of old) {
    const facts = verifiedIssuedCap(app, c.jws);
    if (!facts || facts.iss !== app.userId || facts.sub === "*" || facts.sub === app.userId || facts.kinds[0] !== "*") continue;
    if (!live.has(facts.sub) || subs.has(facts.sub)) continue;
    subs.add(facts.sub);
    const cap = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub: facts.sub, relays: app.relays });
    await app.recordIssued(cap);
    try {
      const d = await app.deliver(facts.sub, "contact", { own: app.userId, sid: "~contact" }, { text: cap });
      if (d.relays.length > 0) reissued++;
    } catch {
      // they'll need a fresh invite
    }
  }
  // Membership statements the revoked device signed: re-sign with n+1 and a fresh cap.
  const rejoined: string[] = [];
  for (const rec of await app.store.listCircles()) {
    const mine = rec.statements[app.userId];
    if (!mine || mine.op !== "join") continue;
    const kid = JSON.parse(Buffer.from(mine.jws.split(".")[0], "base64url").toString()).kid as string;
    if (kid !== did) continue;
    const c = await loadCircle(app.store, rec.cid);
    if (!c) continue;
    const cap = createCap(app.device!, app.keys!.cert, { purpose: "join", relays: app.relays });
    const jws = createMembershipStatement(app.signer(), { cid: rec.cid, n: nextMembershipN(rec.myN), op: "join", at: c.chain.head.hash, cap });
    const s = await verifyMembershipStatement(jws, app.signerCtx());
    await recordJoin(app, s);
    await app.recordIssued(cap);
    for (const m of c.chain.head.members) {
      if (m === app.userId) continue;
      await app.deliver(m, "circle", { own: app.userId, sid: "~circle" }, { circles: [], joins: [jws], ops: [] }).catch(() => undefined);
    }
    rejoined.push(rec.cid);
  }
  const warnings = wasKeyholder ? [lostKeyholderWarning(1)] : [];
  for (const w of warnings) app.warn(w);
  return { revoked: did, ver: pub.ver, capsReissued: reissued, rejoined, warnings };
}

// ---------------------------------------------------------------------------
// Linking (§2.4, §5.7)

export interface LinkStart {
  code: string;
  relay: string;
  expiresAt: number;
  /** Waits for the new device's request, asks `confirm`, then certifies it. */
  wait(confirm: (req: { label: string; compareCode: string; did: string }) => Promise<boolean>): Promise<{ did: string; label: string; keyholder: boolean; ver: number }>;
  cancel(): void;
}

export async function linkStart(app: App, opts: { keyholder?: boolean; relay?: string } = {}): Promise<LinkStart> {
  const ik = app.requireKeyholder("Linking a device");
  const v = await app.ownView();
  if (v.devices.length >= MAX_DEVICES) throw new CliError("too_many_devices", `an identity lists at most ${MAX_DEVICES} devices: revoke one first`);
  const relay = opts.relay ? normalizeRelays([opts.relay])[0] : app.relays[0];
  const s = newLinkSecret();
  const lid = linkId(s);
  const pool = await app.connect();
  const conn = await pool.ensure(relay);
  const opened = await conn.request({ t: "link-open", lid });
  if (opened.t !== "ok") throw new CliError("link_failed", `${relay} refused to open a link mailbox (${relayCode(opened.code ?? opened.t)})`);
  const expiresAt = Date.now() + LINK_TTL_SEC * 1000;
  let cancelled = false;
  return {
    code: encodeLinkCode(s, relay),
    relay,
    expiresAt,
    cancel: () => {
      cancelled = true;
    },
    wait: async (confirm) => {
      let req: ReturnType<typeof selectLinkRequest>;
      for (;;) {
        if (cancelled) throw new CliError("cancelled", "link cancelled");
        if (Date.now() >= expiresAt) throw new CliError("link_expired", "the link code expired (10 minutes): start again");
        const entries = await linkGet(conn, lid, "req");
        if (entries === undefined) throw new CliError("link_expired", "the link mailbox is gone: start again");
        try {
          req = selectLinkRequest(s, entries);
        } catch (e) {
          if (e instanceof P2PError && e.reason === "link-multiple-requests") {
            throw new CliError("link_aborted", "more than one device answered this code: someone else saw it. Link aborted; start again on a private screen");
          }
          throw e;
        }
        if (req) break;
        await sleep(app.tun.linkPollMs);
      }
      const ok = await confirm({ label: req.displayLabel, compareCode: req.compareCode, did: req.did });
      if (!ok) throw new CliError("link_declined", "the compare codes didn't match or you declined: nothing was linked");
      const cert = createDeviceCert(ik, { signingPublicKey: req.signingPublicKey, agreementPublicKey: req.agreementPublicKey, ...(req.displayLabel ? { label: req.displayLabel } : {}) });
      const pub = await app.publishNext((p) => {
        p.devices = [...p.devices, req!.did];
        if (opts.keyholder) p.keyholders = [...p.keyholders, req!.did];
        p.certs = [...(p.certs ?? []), cert];
      });
      await app.store.putDeviceCert({ userId: app.userId, did: req.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
      const frame = sealLinkResponse(s, req, { cert, doc: pub.doc, ...(opts.keyholder ? { ik: b64uEncode(ik.secretKey) } : {}) }, app.device!);
      await linkPut(conn, lid, "resp", JSON.stringify(frame));
      // Everything else the new device needs travels by sync.
      await sendSync(app, await exportAll(app), [req.did]);
      return { did: req.did, label: req.displayLabel, keyholder: !!opts.keyholder, ver: pub.ver };
    },
  };
}

/** The identity a link code would make this device part of, shown before anything is kept (LinkJoin.wait). */
export interface LinkIdentity {
  userId: string;
  address: string;
  fingerprint: string;
  /** This device would get the identity key. */
  keyholder: boolean;
}

export interface LinkJoin {
  compareCode: string;
  did: string;
  /**
   * Waits for the other device, then, with `confirm`, shows which identity this device would
   * become and keeps nothing unless it says yes (a code from someone else makes this device theirs).
   */
  wait(confirm?: (who: LinkIdentity) => Promise<boolean>): Promise<{ userId: string; address: string; did: string; keyholder: boolean }>;
}

export async function linkJoin(app: App, code: string, opts: { label?: string; maxWaitMs?: number; allowPrivateRelay?: boolean } = {}): Promise<LinkJoin> {
  if (await app.load(false)) throw new CliError("already_initialized", `${app.home} already holds an identity (${app.userId})`);
  let parsed: { secret: Uint8Array; relay: string };
  try {
    parsed = parseLinkCode(code);
  } catch {
    throw new CliError("usage", "that is not a link code (p2p-link:…@relay)");
  }
  const { secret, relay } = parsed;
  // A link code someone else gave connects to its relay before anyone confirms anything: the same
  // private-address rule as an invite code's relay, unless it is one of the person's own relays
  // (P2P_DEFAULT_RELAYS or config.json: no identity here yet) or they opted in.
  const allowPrivate = opts.allowPrivateRelay || app.env.P2P_ALLOW_PRIVATE_RELAY === "1";
  let own: string[] = [];
  try {
    own = defaultRelays(app.env, app.file);
  } catch {
    // a broken config: no own relays
  }
  const guard = !allowPrivate && !isOwnRelay(relay, own);
  if (guard && isPrivateRelayHost(new URL(relay).hostname)) {
    throw new CliError("private_relay", privateRelayMessage("link code's relay", new URL(relay).hostname));
  }
  const device = generateDeviceKeysV3("p2p:pending");
  const x = generateDeviceKeysV3("p2p:pending");
  const label = (opts.label ?? defaultLabel()).slice(0, 64);
  const req = createLinkRequest(secret, device, x.agreementPublicKey, label);
  const lid = linkId(secret);
  let conn: Awaited<ReturnType<typeof openLinkConnection>>;
  try {
    conn = await openLinkConnection(relay, app.transport, app.tun.connectTimeoutMs, app.progress, guard ? { lookup: privateGuardLookup() } : {});
  } catch (e) {
    if ((e as Error).message?.includes(PRIVATE_RESOLVE_MARK)) {
      const at = /\(([^()]+)\)\s*$/.exec((e as Error).message)?.[1];
      throw new CliError("private_relay", privateRelayMessage("link code's relay", new URL(relay).hostname, at ? { detail: `it resolves to ${at}` } : {}));
    }
    throw e;
  }
  try {
    await linkPut(conn, lid, "req", JSON.stringify(req));
  } catch (e) {
    conn.close();
    throw e;
  }
  return {
    compareCode: linkCompareCode(secret, device.did),
    did: device.did,
    wait: async (confirm) => {
      const deadline = Date.now() + Math.min(LINK_TTL_SEC * 1000, opts.maxWaitMs ?? Infinity);
      let frame: string | undefined;
      try {
        for (;;) {
          if (Date.now() >= deadline) throw new CliError("link_expired", "no answer from the other device within 10 minutes");
          const entries = await linkGet(conn, lid, "resp");
          if (entries === undefined) throw new CliError("link_expired", "the link mailbox is gone (expired or declined)");
          if (entries.length > 0) {
            frame = entries[0];
            break;
          }
          await sleep(app.tun.linkPollMs);
        }
      } finally {
        conn.close();
      }
      const opened = openLinkResponse(secret, device, x.agreementSecretKey, JSON.parse(frame) as Parameters<typeof openLinkResponse>[3]);
      const userId = opened.doc.iss;
      // Nothing is kept before the person says this is their identity: a code from someone else
      // would make this device theirs.
      if (confirm) {
        const who: LinkIdentity = { userId, address: displayAddress(userId, opened.doc.name), fingerprint: displayFingerprint(userId), keyholder: !!opened.ik };
        if (!(await confirm(who))) {
          throw new CliError(
            "link_declined",
            `not linked: nothing was kept on this device. The other device's identity (${who.address}) now lists a device that will never be used: if it is yours after all, remove it there with \`p2p devices revoke ${device.did}\``,
          );
        }
      }
      const keys = newKeysDoc(userId, { ...device, userId }, opened.cert.jws, opened.ik);
      const self: SelfDoc = { name: opened.doc.name, relays: opened.doc.relays, createdAt: Date.now() };
      renewPersonToken(app.home);
      await app.state.put("keys", keys);
      await app.state.put("self", self);
      app.setKeys(keys, self);
      await app.refreshIdentity(userId, opened.doc.relays, { force: true });
      // The bundle came sealed from our own key holder under the link secret: when the relays
      // can't be reached yet, start our own chain from the document it carried.
      if (!(await app.view(userId))?.devices.includes(device.did)) await jumpIdentity(app.store, opened.doc.jws);
      await app.store.putDeviceCert({ userId, did: device.did, exp: opened.cert.exp, jws: opened.cert.jws });
      receiving(app);
      await app.connectAndDrain();
      return { userId, address: displayAddress(userId, opened.doc.name), did: device.did, keyholder: !!opened.ik };
    },
  };
}

// ---------------------------------------------------------------------------
// Backup (§2.7)

export async function backupShow(app: App): Promise<{ phrase: string; words: number }> {
  const ik = app.requireKeyholder("Showing the backup phrase");
  const phrase = backupPhraseFromSeed(ik.secretKey);
  await app.updateSelf((s) => ({ ...s, backupShown: true }));
  return { phrase, words: 24 };
}

/**
 * Restores the identity key on a fresh home: a new key-holding device and
 * the next document version, which by default lists only this device (§2.7:
 * normally revoking devices that were lost). Friendships and circles are not
 * in the phrase: friends' certificates of the old devices stop verifying.
 *
 * review M4: "the relays hold no document" and "the relays couldn't be read"
 * are different. Starting a new chain at version 1 needs `newChain`, and
 * only when at least one relay answered and none holds a document.
 */
export async function backupRestore(
  app: App,
  phrase: string,
  opts: { relays?: string[]; name?: string; keepDevices?: boolean; newChain?: boolean },
): Promise<RestoreResult> {
  if (await app.load(false)) throw new CliError("already_initialized", `${app.home} already holds an identity (${app.userId})`);
  try {
    return await restoreInto(app, phrase, opts);
  } catch (e) {
    await app.close().catch(() => {});
    // review L1: once a publish may have been stored (accepted, or sent with no answer), a relay may
    // hold the restored version, and wiping would strand the only keys of the device it lists.
    if (app.publishMaybeStored) {
      const why = e instanceof Error ? e.message : String(e);
      throw new CliError(
        "restore_interrupted",
        `${why}. A relay may already hold the restored document, so this device's state in ${app.home} was kept: run \`p2p identity republish\` to finish, or move ${app.home} aside and run \`p2p backup restore\` again (that revokes this half-restored device)`,
        { home: app.home, cause: e instanceof CliError ? e.code : "error" },
      );
    }
    // review N-H1: nothing is committed unless a relay took the new version. The home was fresh
    // (checked above), and no relay can hold the new version (every publish was refused outright or
    // never reached a relay), so its state directories go; config.json stays.
    await rm(join(app.home, "cli"), { recursive: true, force: true });
    await rm(join(app.home, "v3"), { recursive: true, force: true });
    throw e;
  }
}

export interface RestoreResult {
  userId: string;
  address: string;
  did: string;
  ver: number;
  revoked: string[];
  warnings: string[];
  merged: number;
  /** Relays that didn't accept the restored document (R3-M2). */
  failed: { relay: string; code: string }[];
}

async function restoreInto(app: App, phrase: string, opts: { relays?: string[]; name?: string; keepDevices?: boolean; newChain?: boolean }): Promise<RestoreResult> {
  let ik;
  try {
    ik = identityKeyFromBackupPhrase(phrase);
  } catch (e) {
    throw new CliError("bad_phrase", (e as Error).message);
  }
  const relays = opts.relays && opts.relays.length > 0 ? normalizeRelays(opts.relays) : defaultRelays(app.env, app.file);
  if (relays.length === 0) throw new CliError("no_relays", "pass --relay with one of the relays your identity uses (or set P2P_DEFAULT_RELAYS)");
  // Which relays answered, and with what.
  let reachable = 0;
  let found = 0;
  for (const r of relays) {
    try {
      found += (await fetchTips(app.transport(r), ik.userId, app.tun.connectTimeoutMs, app.progress)).length;
      reachable++;
    } catch {
      // unreachable or erroring relay
    }
  }
  if (reachable === 0) throw new CliError("unreachable", "none of those relays could be read: try again when one is reachable (nothing was changed)");
  if (found === 0 && !opts.newChain) {
    throw new CliError(
      "no_document",
      "no relay you named holds a document for this identity. Name the relays your identity uses (--relay), or pass --new-chain to start a new history at version 1",
    );
  }
  const device = generateDeviceKeysV3(ik.userId);
  const cert = createDeviceCert(ik, { signingPublicKey: device.signingPublicKey, agreementPublicKey: device.agreementPublicKey, label: defaultLabel() });
  const keys = newKeysDoc(ik.userId, device, cert, ik);
  const self: SelfDoc = { name: opts.name ?? defaultName(), relays, createdAt: Date.now(), backupShown: true };
  app.setKeys(keys, self);
  // The relays hold a document that doesn't list this device yet: publish over a restricted connection.
  app.allowRestricted = true;
  const warnings: string[] = [];
  if (found === 0) {
    const name = opts.name ?? defaultName();
    const doc = createIdentityDoc(ik, { ver: 1, prev: null, name, relays, devices: [device.did], keyholders: [device.did], by: device.did, certs: [cert] });
    renewPersonToken(app.home);
    await app.state.put("keys", keys);
    await app.state.put("self", { ...self, name });
    app.setKeys(keys, { ...self, name });
    await app.store.putDeviceCert({ userId: ik.userId, did: device.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
    await addIdentityVersion(app.store, doc);
    await app.connect({ allowNone: true });
    const r = await app.publishDoc(doc, relays);
    if (r.ok.length === 0) throw new CliError("not_published", `no relay accepted the new identity document (${r.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}); nothing was restored`);
    warnings.push("started a new identity history at version 1 (--new-chain)");
    for (const w of warnings) app.warn(w);
    if (r.failed.length > 0) warnings.push(`RESTORE INCOMPLETE: ${r.failed.length} relays didn't take the new document (${r.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")})`);
    for (const w of warnings.slice(1)) app.warn(w);
    return { userId: ik.userId, address: displayAddress(ik.userId, name), did: device.did, ver: 1, revoked: [], warnings, merged: 0, failed: r.failed };
  }
  // Strict: the head must be confirmed on the relays before building on it.
  const existing = await app.refreshIdentity(ik.userId, relays, { force: true, strict: true });
  if (!existing) throw new CliError("refresh_failed", "couldn't fit the relays' identity document");
  renewPersonToken(app.home);
  await app.state.put("keys", keys);
  await app.store.putDeviceCert({ userId: ik.userId, did: device.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
  await app.state.put("self", { ...self, name: existing.head.name, relays: existing.head.relays });
  app.setKeys(keys, { ...self, name: existing.head.name, relays: existing.head.relays });
  const revoked = opts.keepDevices ? [] : existing.devices;
  await app.connect({ allowNone: true });
  const pub = await app.publishNext(
    (p) => {
      if (!opts.keepDevices) {
        p.devices = [];
        p.keyholders = [];
        p.certs = [];
      }
      if (p.devices.length >= MAX_DEVICES) throw new CliError("too_many_devices", "your identity already lists 10 devices: restore without --keep-devices");
      p.devices = [...p.devices, device.did];
      p.keyholders = [...p.keyholders, device.did];
      if (opts.name) p.name = opts.name;
    },
    { restoring: true },
  );
  if (pub.ok.length === 0) {
    throw new CliError("not_published", `no relay accepted the restored identity document (${pub.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}); nothing was restored`);
  }
  const lostKeyholders = revoked.filter((d) => existing.keyholders.includes(d));
  if (lostKeyholders.length > 0) warnings.push(lostKeyholderWarning(lostKeyholders.length));
  // R3-M2: a relay that refused keeps serving the old document (which doesn't list this device).
  if (pub.failed.length > 0) {
    warnings.push(
      `RESTORE INCOMPLETE: ${pub.failed.length} of your relays didn't take the new document (${pub.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}). Until they do, they still list your old devices and refuse this one; run \`p2p identity republish\` once they're reachable (it's also retried on every connect)`,
    );
  }
  for (const w of warnings) app.warn(w);
  return { userId: ik.userId, address: displayAddress(ik.userId, opts.name ?? existing.head.name), did: device.did, ver: pub.ver, revoked, warnings, merged: pub.merged, failed: pub.failed };
}

/** review H2/L5: revoking a key holder doesn't take the identity key back. */
export function lostKeyholderWarning(n: number): string {
  return `${n === 1 ? "a revoked device was a key holder: it" : `${n} revoked devices were key holders: they`} still hold your identity key and could publish new versions, and occupy the relays' restricted connection slots for your identity. Only identity rotation neutralises a lost key holder: run \`p2p identity rotate\` (§2.8) from a key holder you still have`;
}

// ---------------------------------------------------------------------------
// Profile (draft 3 additions P1)

const MAGIC: [string, number[]][] = [
  ["png", [0x89, 0x50, 0x4e, 0x47]],
  ["jpeg", [0xff, 0xd8, 0xff]],
  ["gif", [0x47, 0x49, 0x46, 0x38]],
];

/** An avatar value: an https URL or data: URI as given, or an image file made into a data: URI (≤ 4 KiB). */
export async function avatarValue(input: string, read: (p: string) => Promise<Uint8Array> = (p) => readFile(p)): Promise<string> {
  if (/^https:\/\//i.test(input) || input.startsWith("data:")) return input;
  let bytes: Uint8Array;
  try {
    bytes = await read(input);
  } catch {
    throw new CliError("usage", `--avatar ${input} is not an https URL, a data: URI or a readable image file`);
  }
  let mime = MAGIC.find(([, m]) => m.every((b, i) => bytes[i] === b))?.[0];
  if (!mime && bytes.length > 12 && Buffer.from(bytes.slice(0, 4)).toString() === "RIFF" && Buffer.from(bytes.slice(8, 12)).toString() === "WEBP") mime = "webp";
  if (!mime) throw new CliError("usage", "--avatar must be a PNG, JPEG, WebP or GIF image (SVG is not allowed)");
  const uri = `data:image/${mime};base64,${Buffer.from(bytes).toString("base64")}`;
  if (uri.length > PROFILE_AVATAR_DATA_MAX) {
    throw new CliError("avatar_too_large", `the avatar is ${uri.length} bytes as a data: URI; the cap is ${PROFILE_AVATAR_DATA_MAX} (4 KiB): use a smaller image or an https URL`);
  }
  return uri;
}

export async function profileSet(app: App, opts: { bio?: string; avatar?: string; links?: string[]; clear?: boolean }): Promise<{ profile: DisplayProfile; ver: number }> {
  const avatar = opts.avatar !== undefined && opts.avatar !== "" ? await avatarValue(opts.avatar) : opts.avatar;
  await app.connect({ allowNone: true });
  let pub;
  try {
    pub = await app.publishNext((p) => {
      const cur: Profile = opts.clear ? {} : { ...(p.profile ?? {}) };
      if (opts.bio !== undefined) {
        if (opts.bio === "") delete cur.bio;
        else cur.bio = opts.bio;
      }
      if (avatar !== undefined) {
        if (avatar === "") delete cur.avatar;
        else cur.avatar = avatar;
      }
      if (opts.links !== undefined) {
        if (opts.links.length === 0) delete cur.links;
        else cur.links = opts.links;
      }
      if (Object.keys(cur).length === 0) delete p.profile;
      else p.profile = cur;
    });
  } catch (e) {
    if (e instanceof P2PError && e.reason === "malformed") throw new CliError("bad_profile", e.message);
    throw e;
  }
  const v = await app.ownView();
  return { profile: displayProfile(v.head.profile), ver: pub.ver };
}

export async function profileShow(app: App, who?: string): Promise<{ userId: string; address: string; profile: DisplayProfile }> {
  const u = who ? await app.resolveUser(who) : app.userId;
  const v = u === app.userId ? await app.ownView() : await app.viewFor(u);
  if (!v) throw new CliError("unknown_user", `no identity document for ${u}`);
  return { userId: u, address: await app.addressOf(u), profile: displayProfile(v.head.profile) };
}

// ---------------------------------------------------------------------------
// Proofs (§2.6)

export interface ProofAddResult {
  kind: "github" | "dns";
  claim: string;
  loc?: string;
  proof?: string;
  ver?: number;
  /** What the user must publish at the counterpart. */
  publish: string;
  pending?: boolean;
}

export async function proofAdd(app: App, kind: string, claimRaw: string, opts: { gist?: string }): Promise<ProofAddResult> {
  const ik = app.requireKeyholder("Signing a proof");
  const claim = claimRaw.trim().toLowerCase();
  if (kind === "github") {
    if (!opts.gist) {
      return {
        kind,
        claim,
        pending: true,
        publish: `1. Create a public gist as ${claim} at https://gist.github.com (any file name, e.g. p2p-proof.md; any content for now).\n2. Run: p2p proof add github ${claim} --gist <gist id>\n3. Replace the gist's content with the proof that command prints.`,
      };
    }
    let loc: string;
    try {
      loc = canonicalProofLoc("github", claim, opts.gist);
    } catch (e) {
      throw new CliError("usage", (e as Error).message);
    }
    const proof = createProof(ik, { kind: "github", claim, loc });
    const pub = await addProof(app, proof, "github", claim);
    return { kind, claim, loc, proof, ver: pub, publish: `Put this exact text in your gist ${loc}:\n${proof}` };
  }
  if (kind === "dns") {
    let loc: string;
    try {
      loc = canonicalProofLoc("dns", claim);
    } catch (e) {
      throw new CliError("usage", (e as Error).message);
    }
    const proof = createProof(ik, { kind: "dns", claim, loc });
    const pub = await addProof(app, proof, "dns", claim);
    return { kind, claim, loc, proof, ver: pub, publish: `Add this DNS TXT record:\n  ${loc}  TXT  "${dnsProofRecord(app.userId)}"` };
  }
  throw new CliError("usage", "proof kinds are github and dns");
}

async function addProof(app: App, proof: string, kind: string, claim: string): Promise<number> {
  await app.connect({ allowNone: true });
  const same = (j: string) => {
    try {
      const p = decodeTyped(j, TYP3.proof).payload;
      return p.kind === kind && p.claim === claim;
    } catch {
      return false;
    }
  };
  const pub = await app.publishNext((p) => {
    p.proofs = [...(p.proofs ?? []).filter((j) => !same(j)), proof];
  });
  return pub.ver;
}

/** Fetchers for the built-in kinds: the GitHub gist API and DNS TXT. */
export function defaultProofFetchers(): ProofFetchers {
  return {
    github: async (loc) => {
      const id = loc.split("/").at(-1)!;
      const res = await fetch(`https://api.github.com/gists/${encodeURIComponent(id)}`, { headers: { accept: "application/vnd.github+json", "user-agent": "peer2peer-cli" } });
      if (!res.ok) return undefined;
      const g = (await res.json()) as { owner?: { login?: string }; files?: Record<string, { content?: string }> };
      if (!g.owner?.login) return undefined;
      return { owner: g.owner.login, files: Object.values(g.files ?? {}).map((f) => f.content ?? "") };
    },
    dnsTxt: async (name) => (await resolveTxt(name)).map((r) => r.join("")),
  };
}

export interface ProofCheck {
  kind: string;
  claim: string;
  loc: string;
  verified: boolean;
  display?: string;
  error?: string;
}

export async function proofVerify(app: App, who: string, fetchers: ProofFetchers = defaultProofFetchers()): Promise<{ userId: string; address: string; proofs: ProofCheck[] }> {
  const u = await app.resolveUser(who);
  const v = u === app.userId ? await app.ownView() : await app.viewFor(u);
  if (!v) throw new CliError("unknown_user", `no identity document for ${who}`);
  const ok = await verifiedProofs(v.head, fetchers);
  const out: ProofCheck[] = [];
  for (const j of v.head.proofs ?? []) {
    const hit = ok.find((p) => p.jws === j);
    if (hit) {
      out.push({ kind: hit.kind, claim: sanitizePeerText(hit.claim, 64), loc: hit.loc, verified: true, display: hit.display });
      continue;
    }
    try {
      const p = verifyProofSignature(j, v.head);
      out.push({ kind: p.kind, claim: sanitizePeerText(p.claim, 64), loc: p.loc, verified: false, error: "the counterpart doesn't hold this proof (or couldn't be fetched)" });
    } catch (e) {
      out.push({ kind: "?", claim: "?", loc: "", verified: false, error: (e as Error).message });
    }
  }
  return { userId: u, address: await app.addressOf(u), proofs: out };
}
