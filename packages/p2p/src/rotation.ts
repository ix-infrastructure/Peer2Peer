// Copyright 2026 Ix Infrastructure Inc.
//
// Identity key rotation (docs/protocol.md §2.8, with the P3 readings): the
// remedy for a lost or stolen key-holding device.
//
// `p2p identity rotate`, on a key-holding device, keeps friends able to
// verify at every step:
//   0. the plan: a new identity key is made (nothing is published yet) and
//      the user sees its fingerprint and which devices would follow, drops
//      any (a lost device must be dropped: `--exclude`), and accepts. Dropped
//      devices are revoked before any link code is minted;
//   1. a new identity key and new device keys for this device (rotation
//      re-keys every device, so this device gets a new did);
//   2. the two-part statement, signed by the old and the new identity key;
//   3. the new identity's version 1, listing only this device, on the same
//      relays;
//   4. each other device of the old identity gets a `sync` from the old
//      identity carrying the statement and a one-time link code minted by the
//      new identity. It is HELD there: the device follows only when its user
//      says so (`p2p identity follow <id>`), and a key-holding device never
//      follows (it alerts, and can contest). A device that doesn't follow in
//      time re-links by hand later (`link join --rotated`);
//   5. friends get a fresh invite from the new identity, bound to them and
//      bundled with the statement (`contact` {rotation, invite}), which their
//      client holds for approval; circles the old identity owns are handed
//      over (add the new identity, then `transfer`, counter-signed here since
//      this device holds both keys), circles it is a member of get the new
//      identity's join with the statement for the owner, and the old
//      identity's leave; proofs are re-signed under the new identity;
//   6. last, the old identity's final version, `devices: []`, carrying the
//      statement (`rotation`, P3): relays then refuse the old dids, and
//      friends refreshing every 10 minutes find it with no push. It needs a
//      backup of the new key or a key-holding follower first (§2.5).
// Then this home becomes the new identity's; the old one is archived in
// `<home>/rotated/`. Every step is recorded in `<home>/rotation/` so an
// interrupted rotation resumes with `--resume`.
//
// The receiving sides live here too. Friends and circle owners act on a
// rotation only once the OLD identity's own published final version carries
// that same statement, so a statement the old identity never published can't
// split its owner from them: a friend's held "moved to a new key" (approved:
// the normal accept, then the old friendship ends locally), a circle owner's
// `rotation-join` (applied by itself only then, with nothing conflicting,
// never carrying admin rights, never past the owner's hold policy), and this
// user's own devices (held, alerting).
//
// Security notes (also in the help and README):
//  - a thief who also has the old identity key can publish a competing
//    rotation. Friends then see a conflict (two rotations from one old id)
//    and nothing is applied; they resolve it out of band, with petnames and
//    proofs, and exchange a fresh invite with the real one. A key holder
//    that sees a rotation it didn't publish contests it
//    (`p2p identity rotate --contest`), which makes that conflict;
//  - rotation can't recover a compromised owner's circles: those need a new
//    circle (§3.3); this hands over only what the old key still controls.

import { copyFile, mkdir, readFile, rename, rm, stat, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import {
  addIdentityVersion,
  applyCircleBundle,
  b64uEncode,
  backupPhraseFromSeed,
  capsToRevokeOnUnfriend,
  createCircleTransferAccept,
  createDeviceCert,
  createIdentityDoc,
  createMembershipStatement,
  createProof,
  createRotation,
  createUnfriendV3,
  decodeTyped,
  displayAddress,
  displayFingerprint,
  dnsProofRecord,
  encodeLinkCode,
  generateDeviceKeysV3,
  generateIdentityKey,
  IdentityChain,
  INVITE_MAX_TTL_SEC,
  blockUser,
  createCap,
  jwsHash,
  LINK_TTL_SEC,
  linkId,
  liveFriendshipsV3,
  loadCircle,
  newLinkSecret,
  nextMembershipN,
  P2PError,
  parseLinkCode,
  recordOwnLeave,
  rotationConflicts,
  rotationKey,
  sealLinkResponse,
  selectLinkRequest,
  storeOfferedCircle,
  TYP3,
  unfriendApplies,
  verifyDeviceCertV3,
  verifyMembershipStatement,
  verifyRotation,
  verifyRotationSignatures,
  verifyUnfriendV3,
  type IdentityKey,
  type RotationStatement,
  type VerifiedIdentityDoc,
  type VerifiedRotation,
} from "@peer2peer/core/v3";
import { FileDocBackend } from "@peer2peer/core/v3/node";
import { App, certDid, defaultLabel, newKeysDoc } from "./app.js";
import { CliError } from "./errors.js";
import { linkGet, linkPut, relayCode, sleep, type RelayConnection } from "./relay-client.js";
import type { HeldItem, SelfDoc } from "./state.js";
import { deliverCircle, memberCaps, ownerPublish, signOwnJoin } from "./circle-ops.js";
import { accept, dropHeld, getHeld, hold, mintInvite, withHeldId } from "./social.js";
import { exportAll, exportCircle, mergeRemovals, sendSync } from "./sync.js";
import { linkJoin } from "./identity.js";
import { makeEvent, receiving, type EventFrom, type NewEvent } from "./inbound.js";

// ---------------------------------------------------------------------------
// The rotating device's record (`<home>/rotation/state.json`)

export type RotationStep = "created" | "published" | "devices" | "social" | "final" | "done";
const STEPS: readonly RotationStep[] = ["created", "published", "devices", "social", "final", "done"];

export interface RotationDeviceRec {
  label: string;
  keyholder: boolean;
  status: "pending" | "followed" | "offline" | "excluded" | "aborted";
  /** The device's did under the new identity, once it followed. */
  newDid?: string;
  /** Why the plan drops it unless the user keeps it explicitly (pre-release re-review N2, L1). */
  why?: string;
  /** False when its label comes only from versions this device didn't publish (untrusted). */
  labelTrusted?: boolean;
}

export interface RotationCircleRec {
  name: string;
  role: "owner" | "member";
  status: "pending" | "done" | "failed" | "skipped";
  reason?: string;
}

export interface RotationState {
  v: 1;
  from: string;
  to: string;
  statement: RotationStatement;
  startedAt: number;
  step: RotationStep;
  /** The user accepted the plan (step `created` only waits for this). */
  accepted?: boolean;
  /** Contesting a rotation this device didn't publish (§2.8: a conflict, so neither applies). */
  contest?: boolean;
  keepKeyholders: boolean;
  devices: Record<string, RotationDeviceRec>;
  /** Excluded devices revoked on the old identity before any link code went out. */
  revoked?: string[];
  plan: { friends: number; owned: number; memberOf: number };
  /** The rotating device (its own signatures count as trusted). */
  selfDid?: string;
  /**
   * pre-release re-review M1: per friend, the device that signed our side of each
   * stored friendship (not ended by an unfriend), and whether it verifies now.
   */
  friendSigners?: Record<string, { did: string; live: boolean }[]>;
  /** Friends the plan leaves out by default that the user chose to invite anyway (`--invite`). */
  inviteOptIn?: string[];
  friends: Record<string, "pending" | "sent" | "failed">;
  /** When `--resend` sent invites (ms), for the relays' per-sender contact limit. */
  resendAt?: number[];
  circles: Record<string, RotationCircleRec>;
  proofs?: { kind: string; claim: string; publish: string }[];
  finalVer?: number;
  /** False when a contest's final version couldn't reach any relay (they already refuse the old devices). */
  finalPublished?: boolean;
  backupFile?: string;
  /** Where the old home went, once this home is the new identity's. */
  archive?: string;
}

const rotationDir = (home: string) => join(home, "rotation");
const newHomeOf = (home: string) => join(rotationDir(home), "new");
const followHomeOf = (home: string) => join(rotationDir(home), "follow");

function stateBackend(home: string): FileDocBackend {
  return new FileDocBackend(rotationDir(home));
}

export async function readRotationState(home: string): Promise<RotationState | undefined> {
  return (await stateBackend(home).read("state")) as RotationState | undefined;
}

async function saveState(home: string, s: RotationState): Promise<void> {
  const b = stateBackend(home);
  await b.withLock(() => b.write("state", s));
}

async function dropState(home: string): Promise<void> {
  await rm(join(rotationDir(home), "state.json"), { force: true });
  await rm(newHomeOf(home), { recursive: true, force: true });
}

const after = (s: RotationState, step: RotationStep) => STEPS.indexOf(s.step) >= STEPS.indexOf(step);

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/** An App on another home that reaches the relays the same way (config.json is copied). */
async function appAt(app: App, home: string): Promise<App> {
  await mkdir(home, { recursive: true, mode: 0o700 });
  if (await exists(join(app.home, "config.json"))) await copyFile(join(app.home, "config.json"), join(home, "config.json"));
  return new App({ env: { ...app.env, P2P_HOME: home }, io: app.io });
}

/**
 * The directory moves of a home swap, idempotent (an interrupted swap
 * finishes on the next run): the old `cli`, `v3` and `cursors` go to
 * `<home>/rotated/<tag>/`, `src`'s take their place.
 */
async function moveHomes(home: string, src: string, tag: string): Promise<string> {
  const archive = join(home, "rotated", tag);
  await mkdir(archive, { recursive: true, mode: 0o700 });
  const srcHasState = await exists(join(src, "cli"));
  for (const d of ["cli", "v3", "cursors"]) {
    if (srcHasState && (await exists(join(home, d))) && !(await exists(join(archive, d)))) await rename(join(home, d), join(archive, d));
  }
  for (const d of ["cli", "v3"]) {
    if ((await exists(join(src, d))) && !(await exists(join(home, d)))) await rename(join(src, d), join(home, d));
  }
  await rm(src, { recursive: true, force: true });
  // A lock something still held when its directory moved belongs to nobody now.
  for (const d of ["cli", "v3"]) await rm(join(archive, d, ".lock"), { force: true });
  return archive;
}

/**
 * Makes `src` (a home holding the new identity) this home's identity, after
 * the old identity's work here has stopped (moveHomes).
 */
export async function adoptHome(app: App, src: string, tag: string): Promise<string> {
  // Nothing of the old identity may still be writing: an envelope handled mid-swap would take its
  // lock into the archive (or write the old identity's state into the new home).
  await app.close();
  const home = app.home;
  // Let in-flight work of the old identity finish (a refresh after a relay refused it, say): take
  // each store's lock once, so nothing holds it while the directories move.
  // (Only where the directory is still there: taking a lock creates it.)
  if (await exists(join(home, "cli"))) await app.state.backend.withLock(async () => {});
  if (await exists(app.store.dir)) await new FileDocBackend(app.store.dir).withLock(async () => {});
  return moveHomes(home, src, tag);
}

/** Re-points `app` at whatever identity its home now holds (after adoptHome). */
async function reload(app: App): Promise<void> {
  await app.close();
  await app.load(true);
}

function certLabel(cert: string | undefined): string {
  if (!cert) return "";
  try {
    const l = decodeTyped(cert, TYP3.device).payload.label;
    return typeof l === "string" ? l : "";
  } catch {
    return "";
  }
}

/** Our own identity's chain, verified (or undefined); pending heads never narrow our own view (#65 review M1). */
async function ownChain(app: App): Promise<IdentityChain | undefined> {
  const stored = await app.store.getIdentity(app.userId);
  return stored && stored.versions.length > 0 ? IdentityChain.fromStored({ ...stored, pendingHeads: [] }) : undefined;
}

/**
 * The newest version of our identity that is not a rotation's final one:
 * the head when nothing rotated it, else the version a rotation tip was
 * built on (what a contest builds on, and lists the devices from).
 */
async function preRotationHead(app: App): Promise<VerifiedIdentityDoc | undefined> {
  const chain = await ownChain(app);
  if (!chain) return undefined;
  const tips = chain.tips();
  const plain = tips.find((t) => t.rotation === undefined);
  if (plain) return plain;
  for (const t of tips) {
    const p = t.prev ? chain.get(t.prev) : undefined;
    if (p && p.rotation === undefined) return p;
  }
  return undefined;
}

/** Rotations our identity's held tips carry that this device didn't publish (its publish log). */
async function foreignRotations(app: App): Promise<{ hash: string; rotation: VerifiedRotation }[]> {
  const chain = await ownChain(app);
  if (!chain) return [];
  const log = await app.store.getPublishLog();
  const out: { hash: string; rotation: VerifiedRotation }[] = [];
  for (const t of chain.tips()) {
    if (t.rotation === undefined || log.published.includes(t.hash)) continue;
    try {
      const r = verifyRotationSignatures(t.rotation);
      if (r.from === app.userId) out.push({ hash: t.hash, rotation: r });
    } catch {
      // not a valid statement
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Alerts: a rotation of our identity this device didn't publish

/**
 * §2.8, compromise: a rotation of this user's identity that this device
 * didn't publish (judged by its publish log) is raised loudly, once per
 * statement: a stderr line, a `p2p.alert` watch event (the mod shows it on
 * its status line). A key holder is told to contest it.
 */
export async function raiseRotationAlert(app: App, r: VerifiedRotation, by?: string): Promise<boolean> {
  const key = rotationKey(r.statement);
  const fresh = await app.state.update("rotationAlerts", (cur = []) => (cur.includes(key) ? { result: false } : { next: [...cur, key].slice(-64), result: true }));
  if (!fresh) return false;
  const label = by ? certLabel((await app.view(app.userId))?.head.certs?.find((c) => certDid(c) === by)) : "";
  const fp = displayFingerprint(r.to);
  const who = by ? ` by your device ${label ? `"${label}" ` : ""}(${by})` : "";
  const what = app.isKeyholder
    ? "If you didn't start this, someone holds your identity key: contest it now with `p2p identity rotate --contest` (your friends then see a conflict and apply neither)"
    : "Follow it only if you started it yourself. If you didn't, someone holds your identity key: contest it from a key-holding device (`p2p identity rotate --contest`)";
  app.io.err(`ALERT: your identity is being moved to a new key (${fp})${who}. ${what}.`);
  await app.state.addEvents([
    makeEvent(`rotation-alert|${key}`, "p2p.alert", Date.now(), {
      from: { userId: app.userId, did: by ?? app.did, address: await app.addressOf(app.userId), self: true },
      what: "rotation",
      to: r.to,
      fingerprint: fp,
      ...(by ? { by, byLabel: label } : {}),
      keyholder: app.isKeyholder,
      contest: "p2p identity rotate --contest",
    }),
  ]);
  return true;
}

/** Alerts for every rotation on our own held tips this device didn't publish (no network). */
export async function alertForeignRotations(app: App): Promise<void> {
  if (!app.keys) return;
  for (const f of await foreignRotations(app)) await raiseRotationAlert(app, f.rotation);
}

// ---------------------------------------------------------------------------
// p2p identity rotate

export interface RotateOptions {
  resume?: boolean;
  /** Devices that must NOT follow (a lost or stolen one that is still listed): revoked first. */
  exclude?: string[];
  /** Devices the plan dropped by default (added by a version this device didn't publish, or not seen lately) to keep anyway. */
  keep?: string[];
  /** Friends the plan leaves out by default (see RotationPlan.friendsOptIn) to invite anyway. */
  invite?: string[];
  /** Followers that held the old identity key also hold the new one (default: they follow as ordinary devices). */
  keepKeyholders?: boolean;
  /** How long to wait for the other devices to follow (seconds; default the link code's 10 minutes). */
  waitSec?: number;
  /** Asks the user to accept the plan (it names the new fingerprint); `yes` accepts without asking. */
  confirm?: (plan: RotationPlan) => Promise<boolean>;
  yes?: boolean;
  /** Write the new identity's backup phrase to this 0600 file (never overwritten). */
  backupFile?: string;
  /** The same, at `<home>/backup-phrase-<new fingerprint>.txt`. */
  backupFileDefault?: boolean;
  /** A key holder contests a rotation it didn't publish: a competing one, so neither applies. */
  contest?: boolean;
  /** Tests: stop after this step, as an interruption would. */
  stopAfter?: RotationStep;
}

export interface RotationPlan {
  from: string;
  address: string;
  /** The new identity this would move to (made, not yet published). */
  to: string;
  newFingerprint: string;
  follow: { did: string; label: string; keyholder: boolean; labelTrusted: boolean }[];
  /** `why`: dropped by default (keep it with `--keep <did>`); without it, the user dropped it. */
  excluded: { did: string; label: string; keyholder: boolean; labelTrusted: boolean; why?: string }[];
  /** The friends that get the new identity's invite (exactly the ones `friendsOptIn` doesn't leave out). */
  friends: number;
  /**
   * pre-release re-review M1: friendships this device can't vouch for (our side was
   * signed by a device the plan drops or no longer lists, or, rotating
   * normally, the friendship doesn't verify now). Not invited unless the
   * user opts in (`--invite <user>`); `invited` says it did.
   */
  friendsOptIn: { userId: string; address?: string; why: string; invited: boolean }[];
  owned: number;
  memberOf: number;
  contest: boolean;
  backup?: { file: string };
}

export interface RotateResult {
  from: string;
  to: string;
  address: string;
  fingerprint: string;
  did: string;
  step: RotationStep;
  contest?: boolean;
  devices: { followed: { did: string; newDid: string; label: string }[]; offline: { did: string; label: string }[]; excluded: { did: string; label: string }[] };
  friends: { invited: number; failed: string[] };
  circles: { cid: string; name: string; role: string; status: string; reason?: string }[];
  proofs: { kind: string; claim: string; publish: string }[];
  finalVer?: number;
  finalPublished?: boolean;
  backup?: { file: string };
  archive?: string;
  warnings: string[];
}

/**
 * pre-release re-review M1: whether `peer` gets the new identity's invite. Only a
 * friendship whose our-side signature comes from this device or a device
 * that stays in the plan counts (a thief's device can plant friendships with
 * accomplices); rotating normally it must also verify now, while a contest
 * also takes stored ones the other rotation left unverifiable. Anything else
 * is shown in the plan, invited only when the user opts in.
 */
export function friendVerdict(st: RotationState, peer: string): { invite: boolean; why?: string } {
  const entries = st.friendSigners?.[peer] ?? [];
  // A follower that aborted (another device answered its code) is no more trusted than a dropped one.
  const trusted = (did: string) => did === st.selfDid || (st.devices[did] !== undefined && st.devices[did].status !== "excluded" && st.devices[did].status !== "aborted");
  if (entries.some((e) => trusted(e.did) && (st.contest || e.live))) return { invite: true };
  const dropped = entries.map((e) => st.devices[e.did]).find((d) => d?.status === "excluded");
  const why = entries.some((e) => trusted(e.did))
    ? "the friendship doesn't verify now"
    : dropped
      ? `made by a device the plan drops (${dropped.why ?? "you dropped it"})`
      : "made by a device your identity no longer lists";
  return { invite: (st.inviteOptIn ?? []).includes(peer), why };
}

/** The friends the rotation invites (the plan's count is exactly these). */
function invitedFriends(st: RotationState): string[] {
  return Object.keys(st.friendSigners ?? {}).filter((p) => friendVerdict(st, p).invite);
}

function planOf(st: RotationState): RotationPlan {
  const devs = Object.entries(st.devices);
  const optIn = Object.keys(st.friendSigners ?? {})
    .map((userId) => ({ userId, ...friendVerdict(st, userId) }))
    .filter((v) => v.why !== undefined)
    .map((v) => ({ userId: v.userId, why: v.why!, invited: v.invite }));
  return {
    from: st.from,
    address: st.from,
    to: st.to,
    newFingerprint: displayFingerprint(st.to),
    follow: devs.filter(([, d]) => d.status === "pending").map(([did, d]) => ({ did, label: d.label, keyholder: d.keyholder, labelTrusted: d.labelTrusted !== false })),
    excluded: devs
      .filter(([, d]) => d.status === "excluded")
      .map(([did, d]) => ({ did, label: d.label, keyholder: d.keyholder, labelTrusted: d.labelTrusted !== false, ...(d.why ? { why: d.why } : {}) })),
    ...st.plan,
    friends: invitedFriends(st).length,
    friendsOptIn: optIn,
    contest: !!st.contest,
    ...(st.backupFile ? { backup: { file: st.backupFile } } : {}),
  };
}

async function planWithAddress(app: App, st: RotationState): Promise<RotationPlan> {
  const plan = planOf(st);
  const friendsOptIn = await Promise.all(plan.friendsOptIn.map(async (f) => ({ ...f, address: await app.addressOf(f.userId) })));
  return { ...plan, friendsOptIn, address: await app.addressOf(st.from) };
}

/** `--invite`: a friend the plan leaves out by default, invited anyway (the user's explicit choice). */
async function applyInvites(app: App, st: RotationState, invite: readonly string[] = []): Promise<void> {
  for (const u of invite) {
    const peer = await app.resolveUser(u);
    if (!st.friendSigners?.[peer]) throw new CliError("usage", `--invite ${u}: not one of your friends`);
    if (friendVerdict(st, peer).why === undefined) continue;
    st.inviteOptIn = [...new Set([...(st.inviteOptIn ?? []), peer])];
  }
}

/** Every stored friendship no unfriend ended, by friend: the device that signed our side, and whether it verifies now. */
async function friendSigners(app: App): Promise<Record<string, { did: string; live: boolean }[]>> {
  const blocked = new Set((await app.store.listBlocks()).map((b) => b.userId));
  const live = new Set((await liveFriendshipsV3(app.store, app.signerCtx())).map((f) => f.inv));
  const unfriends = await app.store.listUnfriends();
  const out: Record<string, { did: string; live: boolean }[]> = {};
  for (const f of await app.store.listFriendships()) {
    if (unfriends.some((u) => unfriendApplies(f, u))) continue;
    const mine = f.inviter === app.userId;
    const peer = mine ? f.invitee : f.inviter;
    if (peer === app.userId || blocked.has(peer)) continue;
    (out[peer] ??= []).push({ did: mine ? f.inviteDid : f.acceptDid, live: live.has(f.inv) });
  }
  return out;
}

/** Marks `exclude` as dropped in a plan not yet accepted. */
function applyExcludes(st: RotationState, exclude: readonly string[] = [], keep: readonly string[] = []): void {
  for (const d of exclude) {
    const rec = st.devices[d];
    if (!rec) throw new CliError("usage", `--exclude ${d}: not one of your other devices`);
    if (rec.status === "pending") rec.status = "excluded";
  }
  // An explicit keep of a device the plan dropped by default (or the user dropped before).
  for (const d of keep) {
    const rec = st.devices[d];
    if (!rec) throw new CliError("usage", `--keep ${d}: not one of your other devices`);
    if (exclude.includes(d)) throw new CliError("usage", `${d} is both kept and excluded`);
    if (rec.status === "excluded") {
      rec.status = "pending";
      delete rec.why;
    }
  }
}

async function loadOrRecover(app: App, prior: RotationState | undefined, opts: RotateOptions): Promise<RotateResult | undefined> {
  if (app.keys || (await app.load(false))) return undefined;
  // A swap interrupted half way leaves no identity in the home itself: finish it.
  if (opts.resume && prior?.step === "final") return finish(app, prior);
  throw new CliError("no_identity", "no identity here yet: run `p2p init` (or `p2p link join` / `p2p backup restore`)");
}

/**
 * `p2p identity rotate --plan`: makes the new identity key (published only
 * once the plan is accepted) and shows what would happen: the new
 * fingerprint, the devices that would follow, and what moves.
 */
export async function rotatePlan(app: App, opts: RotateOptions = {}): Promise<RotationPlan> {
  const prior = await readRotationState(app.home);
  const recovered = await loadOrRecover(app, prior, opts);
  if (recovered) throw new CliError("rotation_in_progress", "a rotation was just finished here");
  if (prior && prior.step !== "done" && prior.step !== "created") {
    throw new CliError("rotation_in_progress", `a rotation to ${prior.to} is under way: finish it with \`p2p identity rotate --resume\``);
  }
  const st = prior && prior.step === "created" ? prior : await begin(app, opts);
  if (st === prior) applyExcludes(st, opts.exclude, opts.keep);
  await applyInvites(app, st, opts.invite);
  await saveState(app.home, st);
  return planWithAddress(app, st);
}

/** `p2p identity rotate --cancel`: drops a rotation whose plan wasn't accepted (nothing was published). */
export async function rotateCancel(app: App): Promise<{ cancelled: boolean; to?: string }> {
  const st = await readRotationState(app.home);
  if (!st || st.step === "done") return { cancelled: false };
  if (st.step !== "created" || st.accepted) throw new CliError("rotation_in_progress", "the rotation is already under way and can't be cancelled: finish it with `p2p identity rotate --resume`");
  await dropState(app.home);
  if (st.backupFile) app.warn(`the backup phrase of the key that wasn't used is still in ${st.backupFile}: delete it`);
  return { cancelled: true, to: st.to };
}

export async function rotate(app: App, opts: RotateOptions = {}): Promise<RotateResult> {
  const prior = await readRotationState(app.home);
  const recovered = await loadOrRecover(app, prior, opts);
  if (recovered) return recovered;
  if (!app.onEnvelope) receiving(app);
  let st: RotationState;
  if (opts.resume) {
    if (!prior || prior.step === "done") throw new CliError("no_rotation", "there is no rotation in progress here to resume");
    st = prior;
  } else {
    if (prior && prior.step !== "done") throw new CliError("rotation_in_progress", `a rotation to ${prior.to} is in progress: finish it with \`p2p identity rotate --resume\``);
    st = await begin(app, opts);
  }
  // The plan: the devices to drop, then the user's acceptance (never assumed).
  if (st.step === "created" && !st.accepted) {
    applyExcludes(st, opts.exclude, opts.keep);
    await applyInvites(app, st, opts.invite);
    const plan = await planWithAddress(app, st);
    if (!opts.yes) {
      if (!opts.confirm) {
        await saveState(app.home, st);
        throw new CliError("needs_confirmation", "accept the rotation plan first: review it with `p2p identity rotate --plan`, then `p2p identity rotate --resume --yes [--exclude <did>]…`, or run it in a terminal", { plan });
      }
      if (!(await opts.confirm(plan))) {
        if (!opts.resume) await dropState(app.home);
        else await saveState(app.home, st);
        throw new CliError("cancelled", "nothing was changed");
      }
    }
    st.accepted = true;
    await saveState(app.home, st);
  }
  // The swap may have happened already (a crash right after it): finish it, then report.
  if (st.step === "final" || (st.step === "done" && st.archive === undefined)) return finish(app, st);
  app.requireKeyholder("Rotating your identity");
  const napp = await appAt(app, newHomeOf(app.home));
  try {
    await napp.load(true);
    if (napp.userId !== st.to) throw new CliError("internal", "the new identity's keys don't match the rotation in progress");
    const newIk = napp.requireKeyholder("Rotating your identity");
    receiving(napp);
    // A backup asked for later (L3: a resume after `needs_backup`).
    if (!st.backupFile && (opts.backupFile || opts.backupFileDefault)) {
      st.backupFile = await writeBackup(app, newIk, opts);
      await saveState(app.home, st);
    }
    const stop = async (step: RotationStep) => {
      await saveState(app.home, st);
      if (opts.stopAfter === step) throw new CliError("interrupted", `stopped after ${step} (resume with --resume)`);
    };
    if (!after(st, "published")) {
      await publishNew(app, napp);
      st.step = "published";
      await stop("published");
    }
    if (!after(st, "devices")) {
      await followers(app, napp, st, opts);
      st.step = "devices";
      await stop("devices");
    }
    if (!after(st, "social")) {
      await social(app, napp, st, newIk);
      st.step = "social";
      await stop("social");
    }
    if (!after(st, "final")) {
      // §2.5 liveness: the new key must not live on this one device only.
      const keyholderFollower = Object.values(st.devices).some((d) => d.status === "followed" && d.keyholder && st.keepKeyholders);
      if (!st.backupFile && !keyholderFollower) {
        throw new CliError(
          "needs_backup",
          "the new identity key would live on this device only: save its backup first (`p2p identity rotate --resume --backup-file [path]`), then the old identity's final version goes out",
        );
      }
      // §2.8 step 6: last, the old identity's final version.
      const pub = await publishFinal(app, st);
      st.finalVer = pub.ver;
      st.finalPublished = pub.ok.length > 0;
      st.step = "final";
      await stop("final");
    }
  } finally {
    await napp.close();
  }
  return finish(app, st);
}

async function writeBackup(app: App, ik: IdentityKey, opts: RotateOptions): Promise<string | undefined> {
  const file = opts.backupFile ?? (opts.backupFileDefault ? join(app.home, `backup-phrase-${displayFingerprint(ik.userId).replace(/-/g, "")}.txt`) : undefined);
  if (!file) return undefined;
  try {
    await writeFile(file, `${backupPhraseFromSeed(ik.secretKey)}\n`, { mode: 0o600, flag: "wx" });
    await chmod(file, 0o600);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new CliError("exists", `${file} already exists: not overwriting it (pass --backup-file <path>)`);
    throw e;
  }
  return file;
}

/** Steps 1–2 (and the plan): keys, the statement, the new identity's home with version 1 (not yet published). */
async function begin(app: App, opts: RotateOptions): Promise<RotationState> {
  const oldIk = app.requireKeyholder("Rotating your identity");
  if (opts.contest) {
    // The relays may already refuse this device (the other rotation's final version is out).
    await app.connectAndDrain().catch((e) => app.io.err(`p2p: ${(e as Error).message}`));
    await app.refreshIdentity(app.userId, app.relays, { force: true, quiet: true });
  } else {
    await app.connectAndDrain();
    // Build on the relays' head: a stale view could miss a competing rotation or a new device. #67: a listed
    // relay serving versions that don't connect (a thief's, signed with the old identity key) is left out
    // when the others confirm the head (App.ownStrictFallback): rotation is the remedy for exactly that.
    await app.refreshIdentity(app.userId, app.relays, { force: true, strict: true, setAside: { unconnected: true } });
  }
  const view = await app.ownView();
  const foreign = await foreignRotations(app);
  if (view.rotations.length > 0 && !opts.contest) {
    const to = view.rotations.map((r) => verifyRotationSignatures(r).to);
    throw new CliError(
      "identity_rotated",
      `this identity was already rotated to ${to.join(" and ")}${foreign.length > 0 ? ". This device didn't publish that: if you didn't start it, contest it with `p2p identity rotate --contest`" : ""}`,
      { to },
    );
  }
  if (opts.contest) {
    if (view.rotations.length > 0 && foreign.length === 0) throw new CliError("usage", "that rotation is this device's own: there is nothing to contest");
    const alerted = ((await app.state.get("rotationAlerts")) ?? []).length > 0;
    if (foreign.length === 0 && !alerted) throw new CliError("usage", "no rotation of your identity to contest: --contest answers one this device didn't publish");
  } else if (!view.keyholders.includes(app.did)) {
    throw new CliError("device_revoked", "this device is no longer a listed key holder of your identity");
  }
  // What the plan lists from: the head, or (contesting) the version the other rotation replaced.
  const base = view.rotations.length > 0 ? await preRotationHead(app) : view.head;
  if (!base) throw new CliError("refresh_failed", "couldn't find your identity's last version before the rotation");
  const baseDevices = view.rotations.length > 0 ? base.devices : view.devices;
  const baseKeyholders = view.rotations.length > 0 ? base.keyholders : view.keyholders;
  const exclude = [...new Set(opts.exclude ?? [])];
  for (const d of exclude) if (!baseDevices.includes(d) || d === app.did) throw new CliError("usage", `--exclude ${d}: not one of your other devices`);
  const others = baseDevices.filter((d) => d !== app.did);
  const labelOf = (d: string) => certLabel(base.certs?.find((c) => certDid(c) === d));
  const trust = await deviceTrust(app, others, base);
  // pre-release re-review M4: contesting, the device that signed the other rotation's final version, and
  // every other key holder (any of them could have), are dropped unless the user keeps them.
  const contestWhy = new Map<string, string>();
  if (opts.contest) {
    const chain = await ownChain(app);
    for (const f of foreign) {
      const by = chain?.get(f.hash)?.by;
      if (by && by !== app.did) contestWhy.set(by, "signed the rotation you are contesting");
    }
    for (const d of baseKeyholders) if (d !== app.did && !contestWhy.has(d)) contestWhy.set(d, "holds your identity key, so it could have published the rotation you are contesting");
  }
  const whyOf = (d: string) => contestWhy.get(d) ?? trust.get(d)!.why;
  const plan = { friends: 0, owned: 0, memberOf: 0 };
  const signers = await friendSigners(app);
  for (const r of await app.store.listCircles()) {
    const c = await loadCircle(app.store, r.cid);
    if (!c) continue;
    if (c.chain.head.owner === app.userId) plan.owned++;
    else if (r.joinedByMe && c.chain.head.members.includes(app.userId)) plan.memberOf++;
  }
  // 1. A new identity key, and new device keys for this device.
  const newIk = generateIdentityKey();
  const device = generateDeviceKeysV3(newIk.userId);
  const label = certLabel(app.keys!.cert) || defaultLabel();
  const cert = createDeviceCert(newIk, { signingPublicKey: device.signingPublicKey, agreementPublicKey: device.agreementPublicKey, label });
  // 2. The two-part statement, signed by both identity keys.
  const statement = createRotation(oldIk, newIk);
  const doc = createIdentityDoc(newIk, {
    ver: 1,
    prev: null,
    name: base.name,
    relays: [...base.relays],
    devices: [device.did],
    keyholders: [device.did],
    by: device.did,
    certs: [cert],
    ...(base.profile ? { profile: { ...base.profile } } : {}),
  });
  const home = newHomeOf(app.home);
  await rm(home, { recursive: true, force: true });
  const napp = await appAt(app, home);
  const self: SelfDoc = { name: base.name, relays: [...base.relays], createdAt: Date.now() };
  await napp.state.put("keys", newKeysDoc(newIk.userId, device, cert, newIk));
  await napp.state.put("self", self);
  await napp.load(true);
  await addIdentityVersion(napp.store, doc);
  await napp.store.putDeviceCert({ userId: newIk.userId, did: device.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
  await napp.store.recordPublished({ hash: jwsHash(doc), devices: [device.did], relays: base.relays });
  await copyKnowledge(app, napp);
  const st: RotationState = {
    v: 1,
    from: app.userId,
    to: newIk.userId,
    statement,
    startedAt: Date.now(),
    step: "created",
    accepted: false,
    ...(opts.contest ? { contest: true } : {}),
    keepKeyholders: !!opts.keepKeyholders,
    devices: Object.fromEntries(
      others.map((d) => {
        const t = trust.get(d)!;
        const why = whyOf(d);
        // pre-release re-review N2/L1: a device this device didn't list itself, or hasn't seen lately, is dropped
        // unless the user keeps it explicitly (`--keep`): a thief's device never gets a code by default.
        const kept = (opts.keep ?? []).includes(d);
        const dropped = exclude.includes(d) || (why !== undefined && !kept);
        return [
          d,
          {
            label: labelOf(d),
            keyholder: baseKeyholders.includes(d),
            status: dropped ? ("excluded" as const) : ("pending" as const),
            labelTrusted: t.labelTrusted,
            ...(why !== undefined && !kept && !exclude.includes(d) ? { why } : {}),
          },
        ];
      }),
    ),
    plan,
    selfDid: app.did,
    friendSigners: signers,
    friends: {},
    circles: {},
  };
  st.plan.friends = invitedFriends(st).length;
  // The new key's backup, before anything is published: losing this device mid-rotation shouldn't lose it.
  try {
    const file = await writeBackup(app, newIk, opts);
    if (file) st.backupFile = file;
  } catch (e) {
    await rm(home, { recursive: true, force: true });
    throw e;
  }
  await saveState(app.home, st);
  await napp.close();
  return st;
}

/** A device counts as seen lately when it sent this device something, or got a certificate, in the last 30 days. */
export const DEVICE_SEEN_WINDOW_SEC = 30 * 86_400;

/**
 * pre-release re-review N2 and L1: which devices the plan may let follow by default.
 * Only devices listed by versions THIS device published (its publish log)
 * and seen lately: anything else may be a thief's (added by a version this
 * device didn't publish, or long gone) and is dropped unless kept. A label is
 * trusted only when a version this device published carries that device's
 * certificate.
 */
async function deviceTrust(app: App, dids: readonly string[], base: VerifiedIdentityDoc): Promise<Map<string, { why?: string; labelTrusted: boolean }>> {
  const chain = await ownChain(app);
  const log = await app.store.getPublishLog();
  const own = new Map<string, VerifiedIdentityDoc>();
  for (const t of chain?.tips() ?? []) for (const v of chain!.ancestors(t.hash)) if (log.published.includes(v.hash)) own.set(v.hash, v);
  const listed = new Set([...own.values()].flatMap((v) => v.devices));
  const ownCerts = new Set([...own.values()].flatMap((v) => v.certs ?? []));
  const replay = ((await new FileDocBackend(app.store.dir).read("v3-replay")) ?? {}) as Record<string, { lastAt?: Record<string, number> }>;
  const now = Math.floor(Date.now() / 1000);
  const out = new Map<string, { why?: string; labelTrusted: boolean }>();
  for (const d of dids) {
    const cert = base.certs?.find((c) => certDid(c) === d);
    let certIat: number;
    try {
      certIat = cert ? Number(decodeTyped(cert, TYP3.device).payload.iat) || 0 : 0;
    } catch {
      certIat = 0;
    }
    const lastAt = Math.max(0, ...Object.values(replay[d]?.lastAt ?? {})) / 1000;
    const seen = now - Math.max(lastAt, certIat) <= DEVICE_SEEN_WINDOW_SEC;
    const why = !listed.has(d) ? "added by a version you didn't publish" : !seen ? "not seen in the last 30 days" : undefined;
    out.set(d, { ...(why ? { why } : {}), labelTrusted: cert !== undefined && ownCerts.has(cert) });
  }
  return out;
}

/**
 * pre-release re-review L1: during a rotation window (a rotation under way on this
 * device, our identity carrying a rotation, or one this device alerted
 * about), why a friendship synced from another of our devices whose our-side
 * signer is `did` isn't taken: that device is one the rotation drops, or one
 * deviceTrust can't vouch for. Undefined (take it) outside a window, and for
 * this device's own signature.
 */
export async function untrustedImportSigner(app: App, did: string): Promise<string | undefined> {
  if (did === app.did || !app.keys) return undefined;
  const st = await readRotationState(app.home).catch(() => undefined);
  const active = st !== undefined && st.step !== "done";
  if (active && st.devices[did]?.status === "excluded") return st.devices[did].why ?? "a device you dropped from the rotation";
  const rotated = ((await app.view(app.userId))?.rotations.length ?? 0) > 0 || ((await app.state.get("rotationAlerts")) ?? []).length > 0;
  if (!active && !rotated) return undefined;
  const base = await preRotationHead(app);
  if (!base) return "your identity document isn't held here";
  return (await deviceTrust(app, [did], base)).get(did)?.why;
}

/**
 * What the new identity needs to reach the same people: every other
 * identity's verified chain, the circles (as offered, not yet joined), and
 * the local preferences (petnames, blocks). Friendships and caps are not
 * copied: they were the old identity's, and are re-established.
 */
async function copyKnowledge(app: App, napp: App): Promise<void> {
  for (const u of await app.store.listIdentities()) {
    const c = await app.store.getIdentity(u);
    if (c) await napp.store.putIdentity(c);
  }
  for (const [u, p] of Object.entries(await app.store.listPetnames())) await napp.store.setPetname(u, p);
  for (const b of await app.store.listBlocks()) await napp.store.addBlock(b);
  for (const r of await app.store.listCircles()) {
    // The removal record goes along (soak review H1): the new identity may own the circle next.
    await napp.store.putCircle({ cid: r.cid, chain: r.chain, statements: r.statements, joinedByMe: false, ...(r.removed ? { removed: r.removed } : {}) });
  }
}

/** Step 3: the new identity's version 1, on the same relays. */
async function publishNew(app: App, napp: App): Promise<void> {
  const view = await napp.ownView();
  await napp.connect({ allowNone: true });
  const r = await napp.publishDoc(view.head.jws, view.head.relays);
  if (r.ok.length === 0) {
    throw new CliError("not_published", `no relay took the new identity's document (${r.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}); run \`p2p identity rotate --resume\``);
  }
  // The old side verifies the new identity's statements (joins, consents) from its own store.
  await addIdentityVersion(app.store, view.head.jws).catch(() => undefined);
}

/**
 * Dropped devices are revoked on the old identity before any link code goes
 * out (pre-release review H1): a lost device never gets a code, and the relays stop
 * taking it.
 */
async function revokeExcluded(app: App, st: RotationState): Promise<void> {
  // Only what the user dropped: a device the plan merely didn't trust (`why`) gets no code, and the
  // final version revokes it with the rest; revoking it early could end friendships it signed.
  const excluded = Object.entries(st.devices)
    .filter(([, d]) => d.status === "excluded" && d.why === undefined)
    .map(([did]) => did);
  if (excluded.length === 0) return;
  const view = await app.ownView();
  const listed = excluded.filter((d) => view.devices.includes(d));
  if (listed.length > 0 && view.rotations.length === 0) {
    try {
      await app.publishNext((p) => {
        p.devices = p.devices.filter((d) => !listed.includes(d));
        p.keyholders = p.keyholders.filter((d) => !listed.includes(d));
        p.certs = (p.certs ?? []).filter((c) => !listed.includes(certDid(c) ?? ""));
      });
    } catch (e) {
      if (!st.contest) throw e;
      app.warn(`couldn't revoke ${listed.join(", ")} on your old identity (${(e as Error).message})`);
    }
  }
  st.revoked = excluded;
}

/**
 * Step 4: every other device of the old identity gets a `sync` from the old
 * identity with the statement and its own one-time link code, minted by the
 * new identity (a link mailbox opened by this device's new did). The device
 * holds it until its user follows (`p2p identity follow`); a request whose
 * MAC verifies is then certified at once: the code travelled only inside an
 * end-to-end encrypted sync to that one device, so it takes the place of the
 * compare code. Devices that don't answer in time re-link by hand.
 */
async function followers(app: App, napp: App, st: RotationState, opts: RotateOptions): Promise<void> {
  await revokeExcluded(app, st);
  await saveState(app.home, st);
  const pending = Object.entries(st.devices).filter(([, d]) => d.status === "pending");
  if (pending.length === 0) return;
  const pool = await napp.connect();
  const relay = napp.relays[0];
  const conn: RelayConnection = await pool.ensure(relay);
  const open: { did: string; s: Uint8Array; lid: string; keyholder: boolean }[] = [];
  for (const [did, d] of pending) {
    const s = newLinkSecret();
    const lid = linkId(s);
    const opened = await conn.request({ t: "link-open", lid });
    if (opened.t !== "ok") {
      const code = relayCode(opened.code ?? opened.t);
      // A relay caps the link codes one device holds open at once (`full`, 4 by default): the rest re-link by hand.
      if (code !== "full" && code !== "rate-limited") throw new CliError("link_failed", `${relay} refused to open a link mailbox (${code})`);
      app.warn(`${relay} won't hold another link code for this device now (${code}): ${d.label || did} re-links by hand later (\`p2p link join <code> --rotated\`)`);
      d.status = "offline";
      continue;
    }
    const keyholder = d.keyholder && st.keepKeyholders;
    const body = { rotation: { statement: st.statement, link: encodeLinkCode(s, relay), ...(keyholder ? { keyholder: true } : {}) } };
    let reached = false;
    try {
      reached = (await app.deliver(app.userId, "sync", { own: app.userId, sid: "~sync" }, body, { onlyDevices: [did] })).relays.length > 0;
    } catch (e) {
      app.io.err(`couldn't reach your device ${did}: ${(e as Error).message}`);
    }
    if (reached) open.push({ did, s, lid, keyholder });
    else d.status = "offline";
  }
  await saveState(app.home, st);
  const waitSec = Math.max(0, Math.min(opts.waitSec ?? LINK_TTL_SEC, LINK_TTL_SEC));
  if (open.length > 0) {
    app.io.err(`waiting up to ${waitSec}s for ${open.length} of your devices to follow: on each, accept the held rotation (\`p2p held\`, then \`p2p identity follow <id>\`); --wait to change`);
  }
  const deadline = Date.now() + waitSec * 1000;
  while (open.length > 0 && Date.now() < deadline) {
    for (const o of [...open]) {
      const entries = await linkGet(conn, o.lid, "req");
      const rec = st.devices[o.did];
      if (entries === undefined) {
        rec.status = "offline";
        open.splice(open.indexOf(o), 1);
        continue;
      }
      let req;
      try {
        req = selectLinkRequest(o.s, entries);
      } catch (e) {
        if (e instanceof P2PError && e.reason === "link-multiple-requests") {
          // Someone else holds this device's code: link nothing for it.
          app.warn(`more than one device answered the code sent to ${o.did}: not linking it (re-link it by hand)`);
          rec.status = "aborted";
          open.splice(open.indexOf(o), 1);
          continue;
        }
        throw e;
      }
      if (!req) continue;
      const newIk = napp.requireKeyholder("Linking a device");
      const cert = createDeviceCert(newIk, { signingPublicKey: req.signingPublicKey, agreementPublicKey: req.agreementPublicKey, ...(req.displayLabel ? { label: req.displayLabel } : {}) });
      const pub = await napp.publishNext((p) => {
        p.devices = [...p.devices, req.did];
        if (o.keyholder) p.keyholders = [...p.keyholders, req.did];
        p.certs = [...(p.certs ?? []), cert];
      });
      await napp.store.putDeviceCert({ userId: napp.userId, did: req.did, exp: verifyDeviceCertV3(cert).exp, jws: cert });
      const frame = sealLinkResponse(o.s, req, { cert, doc: pub.doc, ...(o.keyholder ? { ik: b64uEncode(newIk.secretKey) } : {}) }, napp.device!);
      await linkPut(conn, o.lid, "resp", JSON.stringify(frame));
      rec.status = "followed";
      rec.newDid = req.did;
      open.splice(open.indexOf(o), 1);
      await saveState(app.home, st);
    }
    if (open.length > 0) await sleep(napp.tun.linkPollMs);
  }
  for (const o of open) st.devices[o.did].status = "offline";
}

/** Sends one friend the new identity's bound invite with the statement. */
async function inviteFriend(app: App, napp: App, peer: string, statement: RotationStatement): Promise<"sent" | "failed"> {
  try {
    const m = await mintInvite(napp, { aud: peer, uses: 3, ttlSec: INVITE_MAX_TTL_SEC });
    const hint = (await app.view(peer))?.relays ?? [];
    const d = await napp.deliver(peer, "contact", { own: napp.userId, sid: "~contact" }, { rotation: statement, invite: m.jws }, { hint });
    return d.relays.length > 0 ? "sent" : "failed";
  } catch (e) {
    app.io.err(`couldn't send ${await app.addressOf(peer)} your new identity: ${(e as Error).message}`);
    return "failed";
  }
}

/** Step 5: friends, circles and proofs move to the new identity. */
async function social(app: App, napp: App, st: RotationState, newIk: IdentityKey): Promise<void> {
  await app.connect({ allowNone: true });
  await napp.connect({ allowNone: true });
  // Friends: a fresh invite from the new identity, bound to the friend, with the statement as proof.
  // Exactly the friends the accepted plan names (friendVerdict, pre-release re-review M1): never one a
  // device the plan drops planted, unless the user opted in.
  if (!st.friendSigners) {
    st.friendSigners = await friendSigners(app);
    st.selfDid ??= app.did;
  }
  const blocked = new Set((await app.store.listBlocks()).map((b) => b.userId));
  for (const peer of invitedFriends(st)) {
    if (blocked.has(peer) || st.friends[peer] === "sent") continue;
    st.friends[peer] = await inviteFriend(app, napp, peer, st.statement);
    await saveState(app.home, st);
  }
  // Circles.
  for (const r of await app.store.listCircles()) {
    const prev = st.circles[r.cid];
    if (prev && (prev.status === "done" || prev.status === "skipped")) continue;
    const c = await loadCircle(app.store, r.cid);
    if (!c) continue;
    const h = c.chain.head;
    const name = h.name;
    // Already handed to the new identity by an interrupted run: finish the hand-over.
    const role = h.owner === app.userId || h.owner === napp.userId ? "owner" : "member";
    // (A failed attempt is retried even though the old identity's leave is already recorded here.)
    if (role === "member" && !prev && !(r.joinedByMe && h.members.includes(app.userId))) continue;
    if (c.chain.frozen) {
      st.circles[r.cid] = { name, role, status: "skipped", reason: `frozen (${c.chain.frozen.reason})` };
      continue;
    }
    try {
      if (role === "owner") await handOver(app, napp, r.cid, newIk);
      else await rejoin(app, napp, r.cid, st.statement);
      st.circles[r.cid] = { name, role, status: "done" };
    } catch (e) {
      st.circles[r.cid] = { name, role, status: "failed", reason: (e as Error).message };
    }
    await saveState(app.home, st);
  }
  const def = app.self?.defaultCircle;
  if (def && (await napp.store.getCircle(def))?.joinedByMe) await napp.updateSelf((s) => ({ ...s, defaultCircle: def }));
  // Proofs, re-signed by the new identity key: the counterparts must be updated by hand.
  const head = await preRotationHead(app);
  if (!st.proofs && head && (head.proofs?.length ?? 0) > 0) {
    const proofs: string[] = [];
    const notes: { kind: string; claim: string; publish: string }[] = [];
    for (const j of head.proofs ?? []) {
      try {
        const p = decodeTyped(j, TYP3.proof).payload as { kind: string; claim: string; loc: string };
        if (p.kind !== "github" && p.kind !== "dns") continue;
        const proof = createProof(newIk, { kind: p.kind, claim: p.claim, loc: p.loc });
        proofs.push(proof);
        notes.push({
          kind: p.kind,
          claim: p.claim,
          publish: p.kind === "github" ? `Replace the content of your gist ${p.loc} with:\n${proof}` : `Change the DNS TXT record ${p.loc} to "${dnsProofRecord(napp.userId)}"`,
        });
      } catch {
        // a proof this CLI can't re-sign (an extension kind): it stays with the old identity
      }
    }
    if (proofs.length > 0) await napp.publishNext((p) => (p.proofs = proofs));
    st.proofs = notes;
  }
  // The followers learn the new identity's state (they linked before step 5).
  await sendSync(napp, await exportAll(napp));
}

/**
 * §2.8 step 6: the old identity's final version, `devices: []` with the
 * statement. It builds on the newest version that isn't a rotation's final
 * one, so when another rotation (one this device didn't publish) is already
 * out, this one is its sibling: a fork that carries two rotations, which
 * friends see as a conflict. Contesting, a relay that already refuses this
 * device is tolerated (the friends' conflict comes from the invites anyway).
 */
async function publishFinal(app: App, st: RotationState): Promise<{ ver: number; ok: string[]; failed: { relay: string; code: string }[] }> {
  const ik = app.requireKeyholder("Publishing your old identity's final version");
  const contesting = st.contest || (await foreignRotations(app)).length > 0;
  await app.connect({ allowNone: true });
  // #67: as in begin, a relay serving versions that don't connect is left out when the others confirm the head.
  await app.refreshIdentity(app.userId, app.relays, contesting ? { force: true, quiet: true } : { force: true, strict: true, setAside: { unconnected: true } });
  const chain = await ownChain(app);
  if (!chain) throw new CliError("no_identity", "this device holds no identity document for its user");
  const tips = chain.tips();
  const mine = tips.find((t) => t.rotation !== undefined && rotationKey(t.rotation) === rotationKey(st.statement));
  if (mine) {
    // Published by an interrupted run: make sure the relays have it.
    const r = await app.publishDoc(mine.jws, mine.relays);
    return { ver: mine.ver, ...r };
  }
  const plain = tips.filter((t) => t.rotation === undefined);
  if (plain.length > 1 && !contesting) {
    // An honest fork: publishNext merges it first.
    const pub = await app.publishNext(() => {}, { rotation: st.statement });
    if (pub.ok.length === 0) throw new CliError("not_published", `no relay took your old identity's final version (${pub.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}); run \`p2p identity rotate --resume\``);
    return pub;
  }
  const base = plain[0] ?? (await preRotationHead(app));
  if (!base) throw new CliError("refresh_failed", "couldn't find your identity's last version before the rotation");
  const doc = createIdentityDoc(ik, { ver: base.ver + 1, prev: base.hash, name: base.name, relays: [...base.relays], devices: [], keyholders: [], by: app.did, rotation: st.statement });
  await addIdentityVersion(app.store, doc);
  await app.store.recordPublished({ hash: jwsHash(doc) });
  const r = await app.publishDoc(doc, [...new Set([...base.relays, ...app.relays])]);
  if (r.ok.length === 0) {
    if (!contesting) throw new CliError("not_published", `no relay took your old identity's final version (${r.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}); run \`p2p identity rotate --resume\``);
    app.warn("no relay took your competing final version (they already refuse your old devices); your friends still see the conflict from your new identity's invites");
  }
  return { ver: base.ver + 1, ...r };
}

/** Copies a circle's chain and statements from `src`'s store into `dst`'s (verified on the way in). */
async function syncCircle(dst: App, src: App, cid: string): Promise<void> {
  const exp = await exportCircle(src, cid);
  if (!exp) return;
  if (!(await dst.store.getCircle(cid))) await storeOfferedCircle(dst.store, exp.versions);
  await applyCircleBundle(dst.store, { circles: exp.versions, joins: exp.statements, ops: [] }, { ...dst.signerCtx(), self: dst.userId });
  await mergeRemovals(dst, cid, exp.removed);
}

/**
 * A circle the old identity owns: add the new identity as a member, have it
 * join, hand ownership over (`transfer`, its consent counter-signed by the
 * new key over {cid, ver, prev}), then the old identity leaves and the new
 * owner drops it. Every version goes to the members as usual.
 */
async function handOver(app: App, napp: App, cid: string, newIk: IdentityKey): Promise<void> {
  const to = napp.userId;
  let c = (await loadCircle(app.store, cid))!;
  if (c.chain.head.owner === app.userId && !c.chain.head.members.includes(to)) await ownerPublish(app, cid, { members: [...c.chain.head.members, to] });
  await syncCircle(napp, app, cid);
  let nc = (await loadCircle(napp.store, cid))!;
  if (nc.book[to]?.op !== "join") await signOwnJoin(napp, cid, nc.chain.head.hash);
  nc = (await loadCircle(napp.store, cid))!;
  await applyCircleBundle(app.store, { circles: [], joins: [nc.book[to].jws], ops: [] }, { ...app.signerCtx(), self: app.userId });
  c = (await loadCircle(app.store, cid))!;
  const h = c.chain.head;
  if (h.owner === app.userId) {
    const consent = createCircleTransferAccept(newIk, { cid, ver: h.ver + 1, prev: h.hash });
    await ownerPublish(app, cid, { newOwner: { userId: to, ik: b64uEncode(newIk.publicKey), transfer: consent } });
  }
  // (Contesting, the old device's leave may not verify any more: the new owner drops it regardless.)
  await leaveAsOld(app, cid).catch((e) => {
    if (!(e instanceof P2PError)) throw e;
  });
  await syncCircle(napp, app, cid);
  nc = (await loadCircle(napp.store, cid))!;
  if (nc.chain.head.owner === to && nc.chain.head.members.includes(app.userId)) {
    await ownerPublish(napp, cid, { members: nc.chain.head.members.filter((m) => m !== app.userId), admins: nc.chain.head.admins.filter((m) => m !== app.userId) });
  }
}

/** The old identity's leave statement, recorded here (sent by the caller). */
async function leaveAsOld(app: App, cid: string): Promise<string> {
  const c = (await loadCircle(app.store, cid))!;
  const mine = c.book[app.userId];
  if (mine?.op === "leave") return mine.jws;
  const jws = createMembershipStatement(app.signer(), { cid, n: nextMembershipN(c.record.myN), op: "leave" });
  await recordOwnLeave(app.store, app.userId, await verifyMembershipStatement(jws, app.signerCtx()));
  return jws;
}

/**
 * A circle the old identity is a member of: the new identity joins (at the
 * held head) and sends the join, the statement and the old identity's leave
 * to the owner, whose client swaps old for new once the old identity's final
 * version carries the statement; the leave also goes to every other member.
 */
async function rejoin(app: App, napp: App, cid: string, statement: RotationStatement): Promise<void> {
  const to = napp.userId;
  await syncCircle(napp, app, cid);
  let nc = (await loadCircle(napp.store, cid))!;
  if (nc.book[to]?.op !== "join") await signOwnJoin(napp, cid, nc.chain.head.hash);
  nc = (await loadCircle(napp.store, cid))!;
  const join = nc.book[to].jws;
  const c = (await loadCircle(app.store, cid))!;
  // Contesting, the old device may no longer be listed (the other rotation's final version), so its
  // leave can't verify: the owner's swap replaces the old identity anyway.
  const leave = await leaveAsOld(app, cid).catch((e) => {
    if (e instanceof P2PError) return undefined;
    throw e;
  });
  const owner = c.chain.head.owner;
  const d = await napp.deliver(owner, "circle", { own: to, sid: "~circle" }, { circles: [], joins: leave ? [join, leave] : [join], ops: [], rotation: statement }, { extraCaps: memberCaps(c, owner) });
  if (d.relays.length === 0) throw new CliError("undelivered", "the owner couldn't be reached");
  if (!leave) return;
  for (const m of c.chain.head.members) {
    if (m === app.userId || m === owner || m === to) continue;
    await deliverCircle(app, m, { joins: [leave] }, memberCaps(c, m)).catch(() => undefined);
  }
}

/** After the final version: this home becomes the new identity's. */
async function finish(app: App, st: RotationState): Promise<RotateResult> {
  if (st.step === "final") {
    st.archive = await adoptHome(app, newHomeOf(app.home), `${st.from.slice(4, 20)}-${st.startedAt}`);
    st.step = "done";
    await saveState(app.home, st);
    await reload(app);
  } else if (st.step === "done" && st.archive === undefined) {
    st.archive = join(app.home, "rotated");
    await saveState(app.home, st);
  }
  return rotateReport(app, st);
}

async function rotateReport(app: App, st: RotationState): Promise<RotateResult> {
  const head = st.step === "done" ? (await app.view(st.to))?.head : undefined;
  const name = head?.name ?? "?";
  const warnings: string[] = [];
  const offline = Object.entries(st.devices).filter(([, d]) => d.status === "offline" || d.status === "aborted");
  if (offline.length > 0) {
    warnings.push(`${offline.length} of your devices didn't follow: on each, run \`p2p link join <code> --rotated\` with a code from \`p2p link start\` here`);
  }
  const failed = Object.entries(st.friends).filter(([, x]) => x === "failed");
  if (failed.length > 0) warnings.push(`${failed.length} friends weren't reached: \`p2p identity rotate --resend\` tries again`);
  if (!st.backupFile) warnings.push("your old backup phrase no longer restores this identity: save the new one (`p2p backup show`)");
  for (const w of warnings) app.warn(w);
  const followed = Object.entries(st.devices)
    .filter(([, d]) => d.status === "followed")
    .map(([did, d]) => ({ did, newDid: d.newDid ?? "", label: d.label }));
  return {
    from: st.from,
    to: st.to,
    address: displayAddress(st.to, name),
    fingerprint: displayFingerprint(st.to),
    did: app.userId === st.to ? app.did : "",
    step: st.step,
    ...(st.contest ? { contest: true } : {}),
    devices: {
      followed,
      offline: offline.map(([did, d]) => ({ did, label: d.label })),
      excluded: Object.entries(st.devices)
        .filter(([, d]) => d.status === "excluded")
        .map(([did, d]) => ({ did, label: d.label })),
    },
    friends: {
      invited: Object.values(st.friends).filter((x) => x === "sent").length,
      failed: failed.map(([u]) => u),
    },
    circles: Object.entries(st.circles).map(([cid, c]) => ({ cid, name: c.name, role: c.role, status: c.status, ...(c.reason ? { reason: c.reason } : {}) })),
    proofs: st.proofs ?? [],
    ...(st.finalVer !== undefined ? { finalVer: st.finalVer } : {}),
    ...(st.finalPublished !== undefined ? { finalPublished: st.finalPublished } : {}),
    ...(st.backupFile ? { backup: { file: st.backupFile } } : {}),
    ...(st.archive ? { archive: st.archive } : {}),
    warnings,
  };
}

/** The most invites `--resend` sends in a rolling hour: under the relays' per-sender contact limit. */
export const RESEND_PER_HOUR = 50;

/**
 * `p2p identity rotate --resend` (after the rotation is done): re-sends the
 * new identity's invite to the friends no invite reached, throttled under
 * the relays' per-sender limit on contacts (at most RESEND_PER_HOUR, or 80%
 * of what a relay advertises, in a rolling hour).
 */
export async function rotateResend(app: App): Promise<{ sent: number; failed: string[]; remaining: number; throttled: boolean }> {
  await app.load(true);
  const st = await readRotationState(app.home);
  if (!st || st.step !== "done" || app.userId !== st.to) throw new CliError("no_rotation", "--resend is for a finished rotation, on the device that rotated");
  if (!app.onEnvelope) receiving(app);
  const pool = await app.connect();
  let limit = RESEND_PER_HOUR;
  for (const r of app.relays) {
    try {
      const advertised = (await pool.ensure(r)).hello?.limits?.contactPerSenderPerHour;
      if (typeof advertised === "number" && advertised > 0) limit = Math.min(limit, Math.max(1, Math.floor(advertised * 0.8)));
    } catch {
      // unreachable: the default applies
    }
  }
  const now = Date.now();
  const recent = (st.resendAt ?? []).filter((t) => now - t < 3_600_000);
  const budget = Math.max(0, limit - recent.length);
  const todo = Object.entries(st.friends)
    .filter(([, x]) => x === "failed")
    .map(([u]) => u);
  let sent = 0;
  for (const peer of todo.slice(0, budget)) {
    st.friends[peer] = await inviteFriend(app, app, peer, st.statement);
    recent.push(Date.now());
    if (st.friends[peer] === "sent") sent++;
    st.resendAt = recent;
    await saveState(app.home, st);
  }
  const failed = Object.entries(st.friends)
    .filter(([, x]) => x === "failed")
    .map(([u]) => u);
  return { sent, failed, remaining: Math.max(0, todo.length - budget), throttled: todo.length > budget };
}

// ---------------------------------------------------------------------------
// Rotations seen (friends' and co-members' clients)

/** Every rotation statement this client has seen, by old userId (from contacts, bundles and documents). */
async function recordRotation(app: App, r: VerifiedRotation): Promise<void> {
  await app.state.update("rotations", (cur = {}) => {
    const list = cur[r.from] ?? [];
    if (list.some((s) => rotationKey(s) === rotationKey(r.statement))) return { result: undefined };
    // Bounded: at most 8 statements per old id, and the most recently seen 256 old ids.
    const { [r.from]: _prev, ...rest } = cur;
    const keys = Object.keys(rest);
    for (const k of keys.slice(0, Math.max(0, keys.length - (MAX_ROTATION_RECORDS - 1)))) delete rest[k];
    return { next: { ...rest, [r.from]: [...list, r.statement].slice(-8) }, result: undefined };
  });
}

const MAX_ROTATION_RECORDS = 256;

/** The verified rotations known for `old`: recorded ones and those its held document's tips carry. */
export async function rotationsFor(app: App, old: string): Promise<VerifiedRotation[]> {
  const out = new Map<string, VerifiedRotation>();
  const list = [...((await app.state.get("rotations"))?.[old] ?? []), ...((await app.view(old))?.rotations ?? [])];
  for (const s of list) {
    try {
      const v = verifyRotationSignatures(s);
      if (v.from === old) out.set(rotationKey(v.statement), v);
    } catch {
      // not a valid statement: ignored
    }
  }
  return [...out.values()];
}

/**
 * §2.8: more than one rotation from the same old id is a conflict
 * (rotationConflicts). Once the user settled one (`p2p identity dispute`),
 * the identities they rejected no longer count; a rotation to anyone new
 * conflicts again.
 */
export async function rotationConflict(app: App, r: VerifiedRotation): Promise<string[] | undefined> {
  const settled = (await app.state.get("rotationResolved"))?.[r.from];
  const all = [r, ...(await rotationsFor(app, r.from))].filter((x) => !settled || !settled.rejected.includes(x.to));
  return rotationConflicts(all).get(r.from);
}

async function recordApproval(app: App, old: string, a: { to: string; kind: "friend" | "circle"; cid?: string }, opts: { fromSync?: boolean } = {}): Promise<void> {
  await app.state.update("rotationApprovals", (cur = {}) => {
    const list = (cur[old] ?? []).filter((x) => !(x.to === a.to && x.kind === a.kind && x.cid === a.cid));
    return { next: { ...cur, [old]: [...list, { ...a, at: Date.now() }].slice(-32) }, result: undefined };
  });
  // pre-release re-review M2: every device of this user learns the approval, so whichever of them sees a
  // later conflict suspends what was carried over.
  if (!opts.fromSync) await sendSync(app, { rotationApprovals: [{ old, ...a }] }).catch(() => 0);
}

/** A `rotationApprovals` sync from another of our devices: recorded here, and a conflict already known disputes now. */
export async function importRotationApprovals(app: App, list: unknown): Promise<void> {
  if (!Array.isArray(list)) return;
  const olds = new Set<string>();
  for (const x of list.slice(0, 64)) {
    const a = x as { old?: unknown; to?: unknown; kind?: unknown; cid?: unknown };
    if (!isUserIdish(a.old) || !isUserIdish(a.to) || (a.kind !== "friend" && a.kind !== "circle")) continue;
    if (a.cid !== undefined && typeof a.cid !== "string") continue;
    await recordApproval(app, a.old, { to: a.to, kind: a.kind, ...(typeof a.cid === "string" ? { cid: a.cid } : {}) }, { fromSync: true });
    olds.add(a.old);
  }
  for (const old of olds) {
    const known = await rotationsFor(app, old);
    const conflict = known.length > 0 ? await rotationConflict(app, known[0]) : undefined;
    if (conflict) await disputeRotation(app, old, conflict);
  }
}

const isUserIdish = (u: unknown): u is string => typeof u === "string" && u.length > 0 && u.length <= 128 && /^[\x21-\x7e]+$/.test(u);

/**
 * pre-release re-review N1: a conflict appeared for `old` after this user had
 * already carried something over through one of its rotations (a friendship
 * accepted, a member swapped into a circle it owns). Every identity it
 * carried over to is suspended at once: blocked locally (no delivery, no
 * session access, no circle standing) and the caps issued to it revoked at
 * its relays. The user is told loudly and offered a resolution: keep one of
 * the identities, or neither (`p2p identity dispute <id>`).
 *
 * Re-review M2: the block and the dispute go to the user's other devices
 * (`sync`), which suspend the same identities and hold the same dispute.
 * M3: on the owner's key-holding device, the suspended identities leave the
 * circles it owns at once (a new version without them); elsewhere the user
 * is told only a key holder can do that (it does when the sync reaches it).
 * M5: an identity the user already kept after checking out of band is not
 * suspended again by a later rotation from the same old id: that is held as
 * a new dispute.
 */
async function disputeRotation(app: App, old: string, claimed: string[], opts: { synced?: string[] } = {}): Promise<void> {
  // Identities the user already rejected stay out (a late sync of a dispute settled since is moot).
  const settled = (await app.state.get("rotationResolved"))?.[old];
  const candidates = claimed.filter((c) => !settled?.rejected.includes(c));
  if (candidates.length < 2) return;
  const approvals = ((await app.state.get("rotationApprovals"))?.[old] ?? []).filter((a) => candidates.includes(a.to));
  const kept = settled?.keep ?? undefined;
  const toSuspend = [...new Set([...approvals.map((a) => a.to), ...(opts.synced ?? []).filter((u) => candidates.includes(u))])].filter((u) => u !== kept);
  if (approvals.length === 0 && toSuspend.length === 0) return;
  const prior = (await app.state.get("disputes"))?.[old];
  if (prior && candidates.every((c) => prior.candidates.includes(c)) && toSuspend.every((u) => prior.suspended.some((s) => s.userId === u))) {
    await removeFromOwnedCircles(app, old, toSuspend);
    return;
  }
  const suspended = [...(prior?.suspended ?? [])];
  for (const to of toSuspend) {
    if (suspended.some((s) => s.userId === to)) continue;
    const wasBlocked = await app.store.isBlocked(to);
    if (!wasBlocked) await app.revokeCaps(await blockUser(app.store, to)).catch(() => 0);
    suspended.push({ userId: to, wasBlocked });
  }
  const all = [...new Set([...(prior?.candidates ?? []), ...candidates])].sort();
  const item = withHeldId({ type: "rotation-dispute", from: old, at: Date.now(), old, candidates: all });
  if (prior) await dropHeld(app, (h) => h.id === prior.heldId);
  await hold(app, item);
  await app.state.update("disputes", (cur = {}) => ({
    next: { ...cur, [old]: { candidates: all, suspended, heldId: item.id, at: Date.now(), ...(prior?.removedFrom ? { removedFrom: prior.removedFrom } : {}) } },
    result: undefined,
  }));
  const ids = suspended.map((s) => s.userId);
  // (Not as `blocks`: each device records its own suspension, so a settlement unblocks only what it blocked.)
  // The statements go along: the other devices verify the conflict themselves (they never act on the claim alone).
  if (!opts.synced) {
    const statements = (await rotationsFor(app, old)).filter((r) => all.includes(r.to)).map((r) => r.statement);
    await sendSync(app, { rotationDispute: { old, candidates: all, suspended: ids, statements } }).catch(() => 0);
  }
  const approved = await Promise.all(ids.map((u) => app.addressOf(u)));
  const others = await Promise.all(all.filter((c) => !ids.includes(c)).map((u) => app.addressOf(u)));
  if (ids.length > 0) {
    app.io.err(
      `ALERT: your earlier approval of ${approved.join(" and ")} moving to a new key is now contested by another key${others.length ? ` (${others.join(", ")})` : ""}. ` +
        `Confirm out of band which one is really them. Until then ${approved.length === 1 ? "it is" : "they are"} suspended (no messages, no session access, no circle standing). ` +
        `Then: \`p2p identity dispute ${item.id} --keep <userId>\`, or \`--neither\``,
    );
  } else {
    app.io.err(
      `ALERT: another move of ${await app.addressOf(old)} to a new key appeared (${others.join(", ")}) after you confirmed ${kept ? await app.addressOf(kept) : "one"} out of band. ` +
        `Nothing new is applied; the one you kept stays as it is. Check again, then: \`p2p identity dispute ${item.id} --keep <userId>\`, or \`--neither\``,
    );
  }
  const from = { userId: old, did: "", address: await app.addressOf(old), self: false };
  const choices = await Promise.all(all.map(async (u) => ({ userId: u, address: await app.addressOf(u), approved: approvals.some((a) => a.to === u) || ids.includes(u) })));
  await app.state.addEvents([
    makeEvent(`rotation-dispute|${old}|${all.join(",")}`, "p2p.alert", Date.now(), { from, what: "rotation-dispute", old, suspended: ids, choices }),
    makeEvent(`rotation-dispute-held|${item.id}`, "p2p.held", Date.now(), { from, held: { id: item.id, type: item.type, old: { userId: old, address: from.address }, choices, conflict: true } }),
  ]);
  await removeFromOwnedCircles(app, old, ids);
}

/** A `rotationDispute` sync from another of our devices: the same identities suspended, the same dispute held. */
/**
 * A `rotationDispute` sync from another of our devices (pre-release third review
 * M-A): never acted on as claimed. Its statements are verified here (each is
 * signed by the old and the new identity key) and the old identity's
 * document refreshed; only a conflict this device then verifies itself
 * counts, and only the identities in that verified conflict that the
 * sending device suspended are suspended here too (on a key holder, also
 * out of the circles it owns). A claim this device can't verify is a quiet
 * note: nothing is blocked, held or published.
 */
export async function importRotationDispute(app: App, body: unknown): Promise<void> {
  const d = body as { old?: unknown; candidates?: unknown; suspended?: unknown; statements?: unknown };
  if (!isUserIdish(d.old) || !Array.isArray(d.candidates) || !Array.isArray(d.suspended)) return;
  const old = d.old;
  const claimed = d.candidates.filter(isUserIdish).slice(0, 16);
  const suspended = d.suspended.filter(isUserIdish).slice(0, 16);
  if (claimed.length < 2) return;
  const unverified = async () =>
    app.io.err(`p2p: another of your devices reported a contested move of ${await app.addressOf(old)} to a new key; this device can't verify it yet (nothing was changed)`);
  // Pre-release fourth review L-C: only about someone this device has to do with (a friend, a circle
  // member, an approval recorded here); anything else is dropped before anything is stored, so
  // junk reports can't push real records out of the bounded rotation list.
  if (!(await concernsUs(app, old))) return unverified();
  // The statements are verified in memory; they are stored only once the conflict verifies.
  const incoming = new Map<string, VerifiedRotation>();
  for (const s of Array.isArray(d.statements) ? d.statements.slice(0, 16) : []) {
    try {
      const r = verifyRotationSignatures(s as RotationStatement);
      if (r.from === old) incoming.set(rotationKey(r.statement), r);
    } catch {
      // not a valid statement: ignored
    }
  }
  await app.refreshIdentity(old, [], { force: true, quiet: true }).catch(() => undefined);
  const settled = (await app.state.get("rotationResolved"))?.[old];
  const all = new Map(incoming);
  for (const r of await rotationsFor(app, old)) all.set(rotationKey(r.statement), r);
  const conflict = rotationConflicts([...all.values()].filter((x) => !settled || !settled.rejected.includes(x.to))).get(old);
  const verified = (conflict ?? []).filter((c) => claimed.includes(c));
  if (!conflict || verified.length < 2) return unverified();
  for (const r of incoming.values()) await recordRotation(app, r);
  await disputeRotation(app, old, conflict, { synced: suspended.filter((u) => verified.includes(u)) });
}

/** Whether `old` is someone this device has to do with: a friend (stored), a member of a circle it holds, or an approval recorded here. */
async function concernsUs(app: App, old: string): Promise<boolean> {
  if (((await app.state.get("rotationApprovals"))?.[old] ?? []).length > 0) return true;
  if ((await app.store.listFriendships()).some((f) => pairOf(f, app.userId, old))) return true;
  for (const r of await app.store.listCircles()) {
    if ((await loadCircle(app.store, r.cid))?.chain.head.members.includes(old)) return true;
  }
  return false;
}

/**
 * pre-release re-review M3: on the owner's key holder, suspended identities leave the
 * circles it owns (a version without them), recorded so a later `--keep`
 * puts the kept one back. Without the key, the user is told loudly.
 */
async function removeFromOwnedCircles(app: App, old: string, ids: readonly string[]): Promise<void> {
  if (ids.length === 0) return;
  const affected: { cid: string; name: string; members: string[]; admins: string[] }[] = [];
  for (const r of await app.store.listCircles()) {
    const c = await loadCircle(app.store, r.cid);
    if (!c || c.chain.head.owner !== app.userId || c.chain.frozen) continue;
    const h = c.chain.head;
    const members = ids.filter((u) => h.members.includes(u));
    if (members.length > 0) affected.push({ cid: r.cid, name: h.name, members, admins: members.filter((u) => h.admins.includes(u)) });
  }
  if (affected.length === 0) return;
  if (!app.isKeyholder) {
    app.io.err(
      `ALERT: ${affected.length === 1 ? "a circle" : "circles"} you own (${affected.map((a) => `"${a.name}"`).join(", ")}) still list${affected.length === 1 ? "s" : ""} the suspended ${ids.length === 1 ? "identity" : "identities"}: ` +
        `only a device that holds your identity key can take ${ids.length === 1 ? "it" : "them"} out. Your key holder does when it next runs (it was told); run \`p2p held\` there now.`,
    );
    return;
  }
  const removed: { cid: string; userId: string; admin: boolean }[] = [];
  for (const a of affected) {
    const h = (await loadCircle(app.store, a.cid))!.chain.head;
    try {
      await ownerPublish(app, a.cid, { members: h.members.filter((m) => !a.members.includes(m)), admins: h.admins.filter((m) => !a.members.includes(m)) });
      for (const u of a.members) removed.push({ cid: a.cid, userId: u, admin: a.admins.includes(u) });
    } catch (e) {
      app.io.err(`ALERT: couldn't take the suspended ${ids.length === 1 ? "identity" : "identities"} out of your circle "${a.name}": ${(e as Error).message}. Run \`p2p held\` again`);
    }
  }
  if (removed.length === 0) return;
  await app.state.update("disputes", (cur = {}) => {
    const d = cur[old];
    if (!d) return { result: undefined };
    const prev = (d.removedFrom ?? []).filter((x) => !removed.some((y) => y.cid === x.cid && y.userId === x.userId));
    return { next: { ...cur, [old]: { ...d, removedFrom: [...prev, ...removed] } }, result: undefined };
  });
}

/**
 * `p2p identity dispute <id> --keep <userId> | --neither`: the user's
 * decision after checking out of band. The rejected identities' friendships
 * end locally, they leave the circles this owner swapped them into, and they
 * stay suspended; the kept one is restored (back into the circles it was
 * taken out of, or, when it was never carried over, its held rotation is
 * applied now) and later rotations to the rejected ones no longer count as a
 * conflict.
 *
 * pre-release re-review M2/M3: only on a key holder. The settlement changes circles
 * this user owns (which only the identity key signs) and goes to every
 * other device of the user, which take it from a key holder only; anywhere
 * else it is refused, loudly, with nothing changed.
 */
export async function resolveDispute(app: App, id: string, choice: { keep?: string; neither?: boolean }): Promise<Record<string, unknown>> {
  const item = await getHeld(app, id);
  if (item.type !== "rotation-dispute" || !item.old) throw new CliError("usage", `${item.id} is not a contested rotation`);
  const old = item.old;
  const d = (await app.state.get("disputes"))?.[old];
  const candidates = d?.candidates ?? item.candidates ?? [];
  if (!choice.neither && !choice.keep) throw new CliError("usage", "choose one: --keep <userId> or --neither");
  if (!app.isKeyholder) {
    throw new CliError(
      "needs_keyholder",
      `settle this on a device that holds your identity key: \`p2p identity dispute\` there changes the circles you own and tells all your devices. Nothing was changed here`,
    );
  }
  const keep = choice.neither ? undefined : await app.resolveUser(choice.keep!);
  if (keep !== undefined && !candidates.includes(keep)) throw new CliError("usage", `${choice.keep} is not one of the identities that claim ${await app.addressOf(old)}`);
  await app.connectAndDrain().catch(() => undefined);
  const rejected = candidates.filter((c) => c !== keep);
  for (const rej of rejected) {
    if ((await app.store.listFriendships()).some((f) => pairOf(f, app.userId, rej))) await endFriendshipLocally(app, rej);
    // Owned circles that still list it (swapped in, not yet taken out) leave it.
    for (const r of await app.store.listCircles()) {
      const c = await loadCircle(app.store, r.cid);
      if (c && c.chain.head.owner === app.userId && !c.chain.frozen && c.chain.head.members.includes(rej)) {
        await ownerPublish(app, r.cid, { members: c.chain.head.members.filter((m) => m !== rej), admins: c.chain.head.admins.filter((m) => m !== rej) });
      }
    }
    // Their suspension stays: they are the user's own block now.
  }
  const out: Record<string, unknown> = { old, keep: keep ?? null, rejected };
  const unblock = await settleLocally(app, old, keep, rejected);
  if (keep !== undefined) {
    const friends = (await app.store.listFriendships()).some((f) => pairOf(f, app.userId, keep));
    if (friends && unblock) {
      // Its caps were revoked when it was suspended: a fresh friend cap.
      const cap = createCap(app.device!, app.keys!.cert, { purpose: "friend", sub: keep, relays: app.relays });
      await app.recordIssued(cap);
      await app.deliver(keep, "contact", { own: app.userId, sid: "~contact" }, { text: cap }).catch(() => undefined);
    }
    // Back into the circles it was taken out of when the dispute began.
    for (const r of (d?.removedFrom ?? []).filter((x) => x.userId === keep)) {
      const c = await loadCircle(app.store, r.cid);
      if (!c || c.chain.head.owner !== app.userId || c.chain.head.members.includes(keep)) continue;
      await ownerPublish(app, r.cid, { members: [...c.chain.head.members, keep], admins: r.admin ? [...c.chain.head.admins.filter((m) => m !== keep), keep] : c.chain.head.admins }, { alsoTo: [keep] });
    }
    const held = (await app.state.get("held")) ?? [];
    const friendItem = held.find((h) => h.type === "rotation" && h.old === old && h.from === keep);
    if (friendItem && !friends) out.friend = (await approveRotation(app, friendItem, { force: true })).friend;
    for (const j of held.filter((h) => h.type === "rotation-join" && h.old === old && h.from === keep)) await approveRotationJoin(app, j, { force: true });
  }
  await dropHeld(app, (h) => h.id === item.id);
  await sendSync(app, { rotationResolved: { old, keep: keep ?? null, rejected } }).catch(() => 0);
  return out;
}

/**
 * The settlement's local half (also applied from a key holder's sync):
 * recorded so the rejected identities no longer conflict, the kept one
 * unblocked unless the user had blocked it before, the dispute and the
 * rejected identities' held items dropped. Returns whether it unblocked.
 */
async function settleLocally(app: App, old: string, keep: string | undefined, rejected: string[], opts: { fromSync?: boolean } = {}): Promise<boolean> {
  const d = (await app.state.get("disputes"))?.[old];
  await app.state.update("rotationResolved", (cur = {}) => ({ next: { ...cur, [old]: { keep: keep ?? null, rejected, at: Date.now() } }, result: undefined }));
  const s = keep !== undefined ? d?.suspended.find((x) => x.userId === keep) : undefined;
  const unblock = !!s && !s.wasBlocked;
  if (unblock) await app.store.removeBlock(keep!);
  await dropHeld(
    app,
    (h) =>
      (h.type === "rotation-dispute" && h.old === old) ||
      ((h.type === "rotation" || h.type === "rotation-join") && h.old === old && (rejected.includes(h.from) || (opts.fromSync === true && h.from === keep))),
  );
  await app.state.update("disputes", (cur = {}) => {
    const { [old]: _gone, ...rest } = cur;
    return { next: rest, result: undefined };
  });
  return unblock;
}

/** A `rotationResolved` sync: taken only from one of our current key holders (they alone settle, see resolveDispute). */
export async function importRotationResolved(app: App, body: unknown, fromDid?: string): Promise<void> {
  const r = body as { old?: unknown; keep?: unknown; rejected?: unknown };
  if (!isUserIdish(r.old) || !Array.isArray(r.rejected) || (r.keep !== null && !isUserIdish(r.keep))) return;
  const view = await app.ownView().catch(() => undefined);
  if (!fromDid || fromDid === app.did || !view?.keyholders.includes(fromDid)) {
    app.io.err(`sync: ignored a settled dispute from ${fromDid ?? "an unknown device"}: only your key holders settle them`);
    return;
  }
  await settleLocally(app, r.old, r.keep ?? undefined, r.rejected.filter(isUserIdish).slice(0, 16), { fromSync: true });
}

/** Whether the old identity's own held document (its final version) carries exactly this statement. */
export async function publishedByOld(app: App, r: VerifiedRotation): Promise<boolean> {
  return ((await app.view(r.from))?.rotations ?? []).some((s) => rotationKey(s) === rotationKey(r.statement));
}

/** Records a rotation and flags the held items it now conflicts with. */
export async function noteRotation(app: App, r: VerifiedRotation): Promise<boolean> {
  await recordRotation(app, r);
  const conflict = await rotationConflict(app, r);
  if (conflict) {
    await disputeRotation(app, r.from, conflict);
    await app.state.update("held", (cur = []) => {
      let changed = false;
      const next = cur.map((h) => {
        if ((h.type === "rotation" || h.type === "rotation-join") && h.old === r.from && h.reason !== "conflict") {
          changed = true;
          return { ...h, reason: "conflict" };
        }
        return h;
      });
      return changed ? { next, result: undefined } : { result: undefined };
    });
  }
  return conflict !== undefined;
}

/** A friend's or co-member's document now carries a rotation (the 10-minute refresh, no push). */
export async function noteDocRotations(app: App, userId: string): Promise<void> {
  for (const s of (await app.view(userId))?.rotations ?? []) {
    try {
      const r = verifyRotationSignatures(s);
      if (r.from === userId) await noteRotation(app, r);
    } catch {
      // ignored
    }
  }
}

function pairOf(f: { inviter: string; invitee: string }, a: string, b: string): boolean {
  return (f.inviter === a && f.invitee === b) || (f.inviter === b && f.invitee === a);
}

/**
 * A friend's new identity sent its invite with the statement (`contact`
 * {rotation, invite}): held as "<friend> moved to a new key" (§2.8: carry a
 * friendship over only after asking). From someone who was never a friend
 * of the old identity, it is an ordinary invite.
 */
export async function onRotationContact(app: App, env: string, at: number, from: EventFrom, rotation: VerifiedRotation, invite: { jws: string; exp: number; iss: string }): Promise<NewEvent[]> {
  const wasFriend = (await app.store.listFriendships()).some((f) => pairOf(f, app.userId, rotation.from));
  if (!wasFriend) {
    const item = withHeldId({ type: "invite", from: invite.iss, at, invite: invite.jws });
    await hold(app, item);
    return [makeEvent(env, "p2p.held", at, { from, held: { id: item.id, type: item.type, exp: invite.exp } })];
  }
  const conflict = await noteRotation(app, rotation);
  const item = withHeldId({ type: "rotation", from: rotation.to, at, invite: invite.jws, rotation: rotation.statement, old: rotation.from });
  await hold(app, conflict ? { ...item, reason: "conflict" } : item);
  return [
    makeEvent(env, "p2p.held", at, {
      from,
      held: { id: item.id, type: item.type, exp: invite.exp, old: { userId: rotation.from, address: await app.addressOf(rotation.from) }, ...(conflict ? { conflict: true } : {}) },
    }),
  ];
}

/** Ends every friendship with `old` on this user's side, locally (its devices are gone), and takes back our caps. */
async function endFriendshipLocally(app: App, old: string): Promise<number> {
  const fs = (await app.store.listFriendships()).filter((f) => pairOf(f, app.userId, old));
  const ctx = app.signerCtx();
  const jwsList: string[] = [];
  for (const inv of new Set(fs.map((f) => f.inv))) {
    const j = createUnfriendV3(app.signer(), { peer: old, inv });
    const u = await verifyUnfriendV3(j, ctx);
    await app.store.addUnfriend({ iss: u.iss, peer: u.peer, inv: u.inv, iat: u.iat, jws: j });
    jwsList.push(j);
  }
  const caps = await capsToRevokeOnUnfriend(app.store, old);
  await app.revokeCaps(caps).catch(() => 0);
  await app.store.removeCapsHeld((c) => c.iss === old);
  if (jwsList.length > 0) await sendSync(app, { unfriends: jwsList });
  return jwsList.length;
}

/**
 * Approving a held "moved to a new key": both halves verified again, the old
 * identity's document refreshed, refused on any conflict and refused unless
 * the old identity's own final version carries this same statement (pre-release review H2: a statement it never published can't split it from its
 * friends); then the normal accept flow with the new identity, and the old
 * friendship ends locally. A petname carries over.
 */
export async function approveRotation(app: App, item: HeldItem, opts: { force?: boolean } = {}): Promise<Record<string, unknown>> {
  if (!item.rotation || !item.invite) throw new CliError("internal", "not a rotation item");
  const rot = verifyRotation(item.rotation);
  await app.connectAndDrain();
  await app.refreshIdentity(rot.from, [], { force: true, quiet: true });
  await noteDocRotations(app, rot.from);
  // `force`: the user settled a contest for this identity out of band (resolveDispute).
  const conflict = opts.force ? undefined : await rotationConflict(app, rot);
  if (conflict) {
    throw new CliError(
      "rotation_conflict",
      `${await app.addressOf(rot.from)} has more than one rotation (to ${conflict.join(" and ")}): someone else holds their old key. Neither is applied: check with them out of band (petnames, proofs), decline these, and exchange a fresh invite`,
      { candidates: conflict },
    );
  }
  if (!opts.force && !(await publishedByOld(app, rot))) {
    throw new CliError(
      "not_published",
      `${await app.addressOf(rot.from)}'s own identity document doesn't carry this move yet (its final version isn't out): approve once it does. Until then it may not be theirs`,
    );
  }
  let accepted: Awaited<ReturnType<typeof accept>> | undefined;
  let failure: unknown;
  try {
    accepted = await accept(app, item.invite);
  } catch (e) {
    // The friendship is recorded even when the accept didn't get out yet.
    if (!(e instanceof CliError) || e.code !== "undelivered") throw e;
    failure = e;
  }
  await recordApproval(app, rot.from, { to: rot.to, kind: "friend" });
  const ended = await endFriendshipLocally(app, rot.from);
  const pet = await app.store.getPetname(rot.from);
  if (pet && !(await app.store.getPetname(rot.to))) {
    await app.store.setPetname(rot.to, pet);
    await sendSync(app, { petnames: { [rot.to]: pet } }).catch(() => 0);
  }
  await dropHeld(app, (h) => h.id === item.id);
  if (failure) throw failure;
  return { type: "rotation", from: rot.from, to: rot.to, friend: accepted!.friend, delivered: accepted!.delivered, endedOld: ended };
}

// ---------------------------------------------------------------------------
// Circle owners: a rotated member's join

export interface RotationJoinOutcome {
  events: NewEvent[];
  /** Circles whose statements from the new identity (and the old one's leave) were handled here (ownerDuties skips them). */
  handled: Set<string>;
  /** The old identity, when a rotation was handled. */
  old?: string;
}

/** Whether this owner holds changes to `cid` for approval (`p2p circle hold`). */
export async function circleHeld(app: App, cid: string): Promise<boolean> {
  return (await app.state.get("circleHold"))?.[cid] === true;
}

type RotationJoinVerdict = { apply: true; adminHeld: boolean } | { apply: false; reason: string };

/**
 * When an owner's client may swap a rotated member in by itself (pre-release review
 * M1, L1): the old identity's published final version carries the
 * statement, no other rotation from it is known, the new identity isn't
 * blocked, the old one is a current member that wasn't removed before, and
 * the owner doesn't hold changes for approval.
 */
async function rotationJoinVerdict(app: App, rot: VerifiedRotation, cid: string): Promise<RotationJoinVerdict> {
  const c = await loadCircle(app.store, cid);
  if (!c) return { apply: false, reason: "not-member" };
  const h = c.chain.head;
  if (await rotationConflict(app, rot)) return { apply: false, reason: "conflict" };
  if (await app.store.isBlocked(rot.to)) return { apply: false, reason: "blocked" };
  if ((c.record.removed ?? []).includes(rot.from) || (c.record.removed ?? []).includes(rot.to)) return { apply: false, reason: "previously-removed" };
  if (!h.members.includes(rot.from)) return { apply: false, reason: "not-member" };
  if (await circleHeld(app, cid)) return { apply: false, reason: "held-by-policy" };
  if (!(await publishedByOld(app, rot))) return { apply: false, reason: "not-final-yet" };
  return { apply: true, adminHeld: h.admins.includes(rot.from) };
}

/** Swaps the old identity for the new as a member (never as an admin: that is held for the owner). */
async function swapMember(app: App, rot: VerifiedRotation, cid: string, withAdmin: boolean) {
  const h = (await loadCircle(app.store, cid))!.chain.head;
  const members = h.members.includes(rot.from) ? h.members.map((m) => (m === rot.from ? rot.to : m)) : [...h.members.filter((m) => m !== rot.to), rot.to];
  const admins = h.admins.filter((m) => m !== rot.from && m !== rot.to);
  if (withAdmin) admins.push(rot.to);
  await recordApproval(app, rot.from, { to: rot.to, kind: "circle", cid });
  return ownerPublish(app, cid, { members, admins }, { alsoTo: [rot.from] });
}

async function holdRotationJoin(app: App, env: string, at: number, from: EventFrom, rot: VerifiedRotation, cid: string, join: string, reason: string): Promise<NewEvent> {
  const c = (await loadCircle(app.store, cid))!;
  const item = withHeldId({ type: "rotation-join", from: rot.to, at, cid, head: c.chain.head.jws, join, rotation: rot.statement, old: rot.from, reason });
  await hold(app, item);
  return makeEvent(
    env,
    "p2p.held",
    at,
    { from, held: { id: item.id, type: item.type, cid, reason, old: { userId: rot.from, address: await app.addressOf(rot.from) }, ...(reason === "conflict" ? { conflict: true } : {}) } },
    {},
    `${join}|${reason}`,
  );
}

/**
 * A `circle` bundle carrying `rotation` with the new identity's join. For a
 * circle this device owns (key holder): the old identity swapped for the new
 * as a member in one version only when rotationJoinVerdict allows it; an
 * admin's rights are held for the owner's approval; anything else is held as
 * `rotation-join` (re-checked when the old identity's final version shows up).
 */
export async function onRotationJoin(
  app: App,
  env: string,
  at: number,
  from: EventFrom,
  statement: RotationStatement,
  sender: string,
  joins: readonly { iss: string; cid: string; op: string; jws: string }[],
): Promise<RotationJoinOutcome> {
  const out: RotationJoinOutcome = { events: [], handled: new Set() };
  let rot: VerifiedRotation;
  try {
    rot = verifyRotation(statement);
  } catch {
    return out;
  }
  if (rot.to !== sender) return out;
  // Only for circles this device owns (a key holder) that the old identity is, or was, a member of:
  // anyone can mint a statement between two fresh keys, so nothing else is recorded.
  const relevant: { s: (typeof joins)[number]; c: NonNullable<Awaited<ReturnType<typeof loadCircle>>> }[] = [];
  for (const s of joins) {
    if (s.iss !== rot.to || s.op !== "join") continue;
    const c = await loadCircle(app.store, s.cid);
    if (!c || c.chain.head.owner !== app.userId || !app.isKeyholder) continue;
    if (!c.chain.head.members.includes(rot.from) && c.book[rot.from] === undefined) continue;
    relevant.push({ s, c });
  }
  if (relevant.length === 0) return out;
  out.old = rot.from;
  await noteRotation(app, rot);
  // The old identity's own document decides (M1): refresh it first.
  await app.refreshIdentity(rot.from, [], { force: true, quiet: true }).catch(() => undefined);
  for (const { s, c } of relevant) {
    out.handled.add(s.cid);
    if (c.chain.head.members.includes(rot.to)) continue;
    const v = await rotationJoinVerdict(app, rot, s.cid);
    if (v.apply) {
      const pub = await swapMember(app, rot, s.cid, false);
      out.events.push(makeEvent(env, "p2p.circle", at, { from, event: "member-rotated", cid: s.cid, ver: pub.ver, old: rot.from, member: rot.to }, {}, `${s.cid}|rot`));
      if (v.adminHeld) out.events.push(await holdRotationJoin(app, env, at, from, rot, s.cid, s.jws, "admin"));
      continue;
    }
    out.events.push(await holdRotationJoin(app, env, at, from, rot, s.cid, s.jws, v.reason));
  }
  return out;
}

/**
 * Held `rotation-join`s waiting for the old identity's final version: applied
 * once it carries the statement (and nothing else stops them). Run after a
 * drain and on watch's 10-minute refresh.
 */
export async function retryRotationJoins(app: App): Promise<NewEvent[]> {
  if (!app.keys || !app.isKeyholder) return [];
  const waiting = ((await app.state.get("held")) ?? []).filter((h) => h.type === "rotation-join" && h.reason === "not-final-yet" && h.rotation && h.cid);
  const events: NewEvent[] = [];
  for (const h of waiting) {
    let rot: VerifiedRotation;
    try {
      rot = verifyRotation(h.rotation!);
    } catch {
      continue;
    }
    await app.refreshIdentity(rot.from, [], { force: true, quiet: true }).catch(() => undefined);
    const c = await loadCircle(app.store, h.cid!);
    if (!c || c.chain.head.owner !== app.userId) continue;
    if (c.chain.head.members.includes(rot.to)) {
      await dropHeld(app, (x) => x.id === h.id);
      continue;
    }
    const v = await rotationJoinVerdict(app, rot, h.cid!);
    if (!v.apply) {
      if (v.reason !== "not-final-yet") await app.state.update("held", (cur = []) => ({ next: cur.map((x) => (x.id === h.id ? { ...x, reason: v.reason } : x)), result: undefined }));
      continue;
    }
    const pub = await swapMember(app, rot, h.cid!, false);
    await dropHeld(app, (x) => x.id === h.id);
    const from = { userId: rot.to, did: "", address: await app.addressOf(rot.to), self: false };
    events.push(makeEvent(`rotation-join|${h.id}`, "p2p.circle", Date.now(), { from, event: "member-rotated", cid: h.cid, ver: pub.ver, old: rot.from, member: rot.to }));
    if (v.adminHeld) events.push(await holdRotationJoin(app, `rotation-join|${h.id}`, Date.now(), from, rot, h.cid!, h.join ?? "", "admin"));
  }
  if (events.length > 0) await app.state.addEvents(events);
  return events;
}

/**
 * Owner: approves a held `rotation-join` (refused on a conflict, or before
 * the old identity's final version carries the statement): swaps old for
 * new, or adds the new identity, and, since the owner approves it here,
 * carries an admin's rights over (`admin` items do only that).
 */
export async function approveRotationJoin(app: App, item: HeldItem, opts: { force?: boolean } = {}): Promise<Record<string, unknown>> {
  if (!item.rotation || !item.cid) throw new CliError("internal", "not a rotation-join item");
  const rot = verifyRotation(item.rotation);
  await app.connectAndDrain();
  await app.refreshIdentity(rot.from, [], { force: true, quiet: true });
  await noteDocRotations(app, rot.from);
  const conflict = opts.force ? undefined : await rotationConflict(app, rot);
  if (conflict) throw new CliError("rotation_conflict", `more than one rotation from ${await app.addressOf(rot.from)} (to ${conflict.join(" and ")}): neither is applied; resolve it out of band`, { candidates: conflict });
  if (!opts.force && !(await publishedByOld(app, rot))) {
    throw new CliError("not_published", `${await app.addressOf(rot.from)}'s own identity document doesn't carry this move yet: approve once its final version is out`);
  }
  const c = await loadCircle(app.store, item.cid);
  if (!c) throw new CliError("not_found", "circle not held");
  const h = c.chain.head;
  let ver = h.ver;
  const wasAdmin = h.admins.includes(rot.from) || h.admins.includes(rot.to) || item.reason === "admin";
  if (!h.members.includes(rot.to) || (wasAdmin && !h.admins.includes(rot.to))) ver = (await swapMember(app, rot, item.cid, wasAdmin)).ver;
  await dropHeld(app, (x) => x.id === item.id);
  return { type: "rotation-join", cid: item.cid, old: rot.from, member: rot.to, ver, admin: wasAdmin };
}

// ---------------------------------------------------------------------------
// The user's other devices: a rotation of our own identity

/**
 * A `sync` from our own (old) identity with `{rotation: {statement, link,
 * keyholder?}}` (pre-release review H2): never followed by itself. On an ordinary
 * device it is held (with the new fingerprint and the sending device) for
 * the user to follow, or not; a key-holding device never follows, it alerts
 * and offers to contest. Only a sync from a current key holder counts, with
 * a statement from our own identity.
 */
export async function noteOwnRotation(app: App, body: unknown, fromDid?: string): Promise<void> {
  if (typeof body !== "object" || body === null) return;
  // Only a key holder can rotate (it holds the identity key): a sync from any other device of ours
  // naming a rotation is ignored, so a lost ordinary device can't move the others away.
  const own = await app.view(app.userId);
  if (!fromDid || !own?.keyholders.includes(fromDid)) {
    app.io.err("ignored a rotation sync from a device that isn't one of your key holders");
    return;
  }
  const b = body as { statement?: RotationStatement; link?: unknown; keyholder?: unknown };
  let r: VerifiedRotation;
  try {
    r = verifyRotation(b.statement as RotationStatement);
    if (typeof b.link !== "string") return;
    parseLinkCode(b.link);
  } catch {
    app.io.err("ignored a rotation sync that doesn't verify");
    return;
  }
  if (r.from !== app.userId) return;
  await raiseRotationAlert(app, r, fromDid);
  if (app.isKeyholder) return;
  const deviceLabel = certLabel(own.head.certs?.find((c) => certDid(c) === fromDid));
  const item = withHeldId({ type: "rotation-follow", from: r.to, at: Date.now(), rotation: r.statement, old: r.from, device: fromDid, deviceLabel, newFingerprint: displayFingerprint(r.to) });
  // The link code is a secret: kept apart from the held item (which is listed), by its id.
  await app.state.update("follows", (cur = {}) => ({ next: { ...cur, [item.id]: { statement: r.statement, link: b.link as string, fromDid, at: Date.now() } }, result: undefined }));
  await hold(app, item);
  await app.state.addEvents([
    makeEvent(`rotation-follow|${item.id}`, "p2p.held", Date.now(), {
      from: { userId: r.to, did: fromDid, address: await app.addressOf(r.to), self: false },
      held: { id: item.id, type: item.type, newFingerprint: item.newFingerprint, device: fromDid, deviceLabel, old: { userId: r.from, address: await app.addressOf(r.from) } },
    }),
  ]);
}

let following = false;

/**
 * `p2p identity follow <id>` (or approving the held item): the user's own
 * decision to move this device with its identity. Links to the new identity
 * with the code the key holder sent, then makes this home the new identity's
 * (the old one archived). A key-holding device never follows. If the key
 * holder isn't answering any more, re-link by hand (`link join --rotated`).
 */
export async function followHeld(app: App, idOrItem: string | HeldItem): Promise<{ userId: string; address: string; did: string; from: string; keyholder: boolean }> {
  await app.load(true);
  const item = typeof idOrItem === "string" ? await getHeld(app, idOrItem) : idOrItem;
  if (item.type !== "rotation-follow" || !item.rotation) throw new CliError("usage", `${item.id} is not a rotation of your identity`);
  if (app.isKeyholder) {
    throw new CliError(
      "keyholder",
      "a key-holding device never follows a rotation: if you started it, link this device to the new identity by hand (`p2p link start` there, `p2p link join <code> --rotated` here); if you didn't, contest it (`p2p identity rotate --contest`)",
    );
  }
  const rec = (await app.state.get("follows"))?.[item.id];
  if (!rec) throw new CliError("not_found", "this rotation's link code is gone: re-link by hand (`p2p link start` on the new identity, `p2p link join <code> --rotated` here)");
  const r = verifyRotationSignatures(rec.statement);
  if (r.from !== app.userId) throw new CliError("wrong_identity", "that rotation is another identity's");
  if (following) throw new CliError("busy", "already following");
  following = true;
  const tmp = followHomeOf(app.home);
  try {
    await rm(tmp, { recursive: true, force: true });
    const napp = await appAt(app, tmp);
    let res;
    try {
      const j = await linkJoin(napp, rec.link, { label: certLabel(app.keys!.cert) || defaultLabel(), maxWaitMs: followWaitMs(app) });
      res = await j.wait();
    } finally {
      await napp.close();
    }
    if (res.userId !== r.to) throw new CliError("wrong_identity", `the link joined ${res.userId}, not ${r.to}`);
    const old = app.userId;
    const tag = `${old.slice(4, 20)}-${Date.now()}`;
    // L4: from here the swap is resumable (recoverInterruptedFollow), even if this process dies.
    await writeFile(join(tmp, "linked.json"), JSON.stringify({ to: r.to, tag }), { mode: 0o600 });
    await adoptHome(app, tmp, tag);
    await reload(app);
    app.io.err(`this device moved with your identity: it is now ${res.address} (${res.did})`);
    await app.state.addEvents([makeEvent(`rotated|${old}|${r.to}`, "p2p.contact", Date.now(), { from: { userId: r.to, did: res.did, address: res.address, self: true }, what: "rotated", old })]);
    return { ...res, from: old };
  } catch (e) {
    if (!(await exists(join(tmp, "linked.json")))) await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    if (e instanceof CliError && (e.code === "wrong_identity" || e.code === "keyholder")) throw e;
    throw new CliError(
      "follow_failed",
      `couldn't follow your identity to its new key (${(e as Error).message}): if the device that rotated has stopped waiting, re-link by hand: \`p2p link start\` on a device of the new identity, then here \`p2p link join <code> --rotated\``,
    );
  } finally {
    following = false;
  }
}

function followWaitMs(app: App): number {
  const v = Number(app.env.P2P_FOLLOW_WAIT_MS ?? "");
  return Number.isFinite(v) && v > 0 ? v : 60_000;
}

/**
 * L4: a follow that linked to the new identity but died before (or while)
 * this home was swapped finishes on the next run: `rotation/follow` then
 * holds the new identity and a `linked.json` marker. Pure file work, run
 * before the home's identity is loaded. Returns true when it finished one.
 */
export async function recoverInterruptedFollow(home: string): Promise<boolean> {
  const tmp = followHomeOf(home);
  let marker: { to?: string; tag?: string };
  try {
    marker = JSON.parse(await readFile(join(tmp, "linked.json"), "utf8")) as { to?: string; tag?: string };
  } catch {
    return false;
  }
  if (!(await exists(join(tmp, "cli"))) && (await exists(join(home, "cli")))) {
    // The new identity is already in place (the swap finished but the marker stayed).
    await rm(tmp, { recursive: true, force: true });
    return false;
  }
  await moveHomes(home, tmp, typeof marker.tag === "string" && /^[\w-]{1,80}$/.test(marker.tag) ? marker.tag : `follow-${Date.now()}`);
  return true;
}

/**
 * `p2p link join <code> --rotated`: a device whose identity was rotated
 * without it re-links by hand. Allowed only when this home's identity
 * carries a rotation (its final version, or a rotation our key holder
 * sent), and only into an identity a rotation names.
 */
export async function relinkRotated(app: App, code: string, opts: { label?: string } = {}) {
  await app.load(true);
  await app.refreshIdentity(app.userId, app.relays, { force: true, quiet: true });
  const targets = new Set<string>();
  const sent = Object.values((await app.state.get("follows")) ?? {}).map((f) => f.statement);
  for (const s of [...((await app.view(app.userId))?.rotations ?? []), ...sent]) {
    try {
      const r = verifyRotationSignatures(s);
      if (r.from === app.userId) targets.add(r.to);
    } catch {
      // ignored
    }
  }
  if (targets.size === 0) throw new CliError("not_rotated", "this device's identity hasn't been rotated: --rotated only re-links a device whose identity moved (§2.8)");
  const tmp = followHomeOf(app.home);
  await rm(tmp, { recursive: true, force: true });
  const napp = await appAt(app, tmp);
  const j = await linkJoin(napp, code, { label: opts.label ?? (certLabel(app.keys!.cert) || defaultLabel()) });
  const old = app.userId;
  return {
    compareCode: j.compareCode,
    did: j.did,
    wait: async () => {
      let res;
      try {
        res = await j.wait();
      } finally {
        await napp.close();
      }
      if (!targets.has(res.userId)) {
        await rm(tmp, { recursive: true, force: true });
        throw new CliError("wrong_identity", `that code links to ${res.userId}, which isn't where your identity moved (${[...targets].join(", ")})`);
      }
      const tag = `${old.slice(4, 20)}-${Date.now()}`;
      await writeFile(join(tmp, "linked.json"), JSON.stringify({ to: res.userId, tag }), { mode: 0o600 });
      await adoptHome(app, tmp, tag);
      await reload(app);
      return { ...res, from: old };
    },
  };
}
