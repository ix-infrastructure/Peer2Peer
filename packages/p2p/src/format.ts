// Copyright 2026 Ix Infrastructure Inc.
//
// Human output. Pure functions over the commands' JSON results, so the
// `--json` shape and the terminal text never drift apart. Every peer string
// reaching here was already passed through the core sanitizer; message text
// (shown raw in JSON) is sanitized for the terminal here.

import { sanitizePeerText } from "@peer2peer/core/v3";
import { renderUnicodeCompact } from "uqr";
import type { Delivery } from "./app.js";
import type { CircleSummary, JoinResult, MemberRow } from "./circle-ops.js";
import type { CodeRow } from "./codes.js";
import type { DeviceRow, WhoamiResult } from "./identity.js";
import type { PeerRow, RosterView } from "./sessions.js";
import type { FriendRow } from "./social.js";
import type { RotateResult, RotationPlan } from "./rotation.js";

export function formatAge(sec: number): string {
  if (sec < 60) return `${Math.max(0, Math.round(sec))}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m`;
  if (sec < 86_400) return `${Math.floor(sec / 3600)}h`;
  return `${Math.floor(sec / 86_400)}d`;
}

export function formatDate(sec: number): string {
  return new Date(sec * 1000).toISOString().slice(0, 10);
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

export function formatCodes(rows: CodeRow[]): string {
  if (rows.length === 0) return "No invite codes. Make one: p2p invite <label>";
  const now = Date.now() / 1000;
  return rows
    .map((r) => {
      const who = r.label ? ` ${r.label}` : "";
      const circle = r.circle ? ` +circle "${r.circle.name}"` : "";
      const to = r.to ? ` (only ${r.to.address})` : "";
      let st: string;
      switch (r.status) {
        case "open":
          st = `open, ${plural(Math.max(1, Math.round((r.exp - now) / 86_400)), "day")} left`;
          break;
        case "evicted":
          st = "evicted by the relay (it was full): make a new code";
          break;
        case "taken":
          st = "TAKEN, but nobody joined yet: if that wasn't them, `p2p invites revoke` refuses the join";
          break;
        case "redeemed":
          st = `redeemed by ${r.redeemedBy?.address ?? "?"} (not them? p2p remove ${r.redeemedBy?.userId ?? ""})`;
          break;
        default:
          st = r.status;
      }
      const shown = r.status === "open" || r.status === "taken" ? r.code : r.code.replace(/[^/]*$/, (c) => `${c.slice(0, 4)}…`);
      return `${shown}${who}${circle}${to}: ${st}`;
    })
    .join("\n");
}

/** "delivered via 2 relays (1 device)". */
export function formatDelivery(d: Pick<Delivery, "relays" | "devices">): string {
  return `delivered via ${plural(d.relays.length, "relay")} (${plural(d.devices, "device")})`;
}

/** A terminal QR code of `text`; empty when it can't be rendered. */
export function qr(text: string): string {
  try {
    return renderUnicodeCompact(text, { border: 1, ecc: "L" });
  } catch {
    return "";
  }
}

function table(rows: string[][]): string {
  if (rows.length === 0) return "";
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => [...(r[i] ?? "")].length)));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? c : c.padEnd(widths[i]))).join("  ").trimEnd()).join("\n");
}

export function formatDevices(rows: DeviceRow[]): string {
  return table([
    ["DEVICE", "LABEL", "ROLE", "CERT EXPIRES"],
    ...rows.map((d) => [`${d.did}${d.thisDevice ? " *" : ""}`, d.label || "-", d.keyholder ? "key holder" : "device", d.certExp ? formatDate(d.certExp) : "-"]),
  ]);
}

export function formatWhoami(r: WhoamiResult): string {
  const lines = [
    `${r.address}`,
    `  userId       ${r.userId}`,
    `  fingerprint  ${r.fingerprint}`,
    `  this device  ${r.did}${r.keyholder ? " (key holder)" : ""}`,
    `  relays       ${r.relays.join(", ")}`,
    `  document     version ${r.doc.ver}, expires ${formatDate(r.doc.exp)}${r.doc.freshness !== "fresh" ? ` (${r.doc.freshness}, ${r.doc.daysPastExp} days past)` : ""}${r.doc.forked ? ", forked" : ""}`,
  ];
  if (r.profile.bio) lines.push(`  bio          ${r.profile.bio}`);
  if (r.profile.links.length > 0) lines.push(`  links        ${r.profile.links.join(" ")}`);
  if (r.defaultCircle) lines.push(`  circle       ${r.defaultCircle} (default)`);
  lines.push("", formatDevices(r.devices));
  for (const w of r.warnings) lines.push("", `! ${w}`);
  return lines.join("\n");
}

export function formatPeers(rows: PeerRow[]): string {
  if (rows.length === 0) return "No live sessions. Friends' and circle-mates' sessions appear here once they post a status.";
  const out: string[] = [];
  for (const r of rows) {
    const who = r.self ? `${r.address} (you${r.thisDevice ? ", this device" : ""})` : r.address;
    const where = [r.repo, r.branch].filter(Boolean).join("@");
    out.push(`${r.live ? (r.state === "busy" ? "●" : "○") : "·"} ${who} [${r.ref}] ${r.label} ${r.state}${where ? `  ${where}` : ""}  ${formatAge(r.ageSec)} ago${r.live ? "" : " (stale)"}`);
    if (r.summary) out.push(`    ${r.summary}`);
    if (r.files.length > 0) out.push(`    files: ${r.files.slice(0, 8).join(", ")}${r.files.length > 8 ? ` +${r.files.length - 8}` : ""}`);
    // Validated by displayStatus: ids, types and states are of strict charsets, tasks and files one sanitized line.
    for (const a of r.agents ?? []) {
      const where = [a.state, a.wt ? `worktree${a.branch ? ` ${a.branch}` : ""}` : ""].filter(Boolean).join(", ");
      const files = a.files?.length ? `: ${a.files.slice(0, 4).join(", ")}${a.files.length > 4 ? ` +${a.files.length - 4}` : ""}` : "";
      out.push(`    ${a.parent ? `  ${a.id} (of ${a.parent})` : a.id} ${a.type} "${a.task}" (${where})${files}`);
    }
    // Extension state (§4.3): only its sanitized fallback line, never a body.
    for (const x of r.xstate ?? []) out.push(`    ${x.kind}: ${x.fallback}`);
  }
  return out.join("\n");
}

export function formatFriends(r: { friends: FriendRow[]; invites: { outgoing: { inv: string; aud: string; exp: number }[]; held: number }; blocked: { address: string }[] }): string {
  const out: string[] = [];
  if (r.friends.length === 0) out.push("No friends yet: `p2p invite` makes a link to send someone.");
  else {
    out.push(
      table([
        ["FRIEND", "SINCE", "STATUS"],
        ...r.friends.map((f) => [f.address, formatDate(f.since), f.canMessage ? "connected" : "waiting for their cap"]),
      ]),
    );
  }
  if (r.invites.outgoing.length > 0) out.push("", `${plural(r.invites.outgoing.length, "open invite")} (yours, not yet accepted)`);
  if (r.invites.held > 0) out.push("", `${plural(r.invites.held, "held item")} waiting for you: \`p2p held\``);
  if (r.blocked.length > 0) out.push("", `blocked: ${r.blocked.map((b) => b.address).join(", ")}`);
  return out.join("\n");
}

export function formatCircles(rows: CircleSummary[]): string {
  if (rows.length === 0) return "No circles: `p2p circle create <name>` or `p2p circle join <link>`.";
  return table([
    ["CIRCLE", "NAME", "ROLE", "MEMBERS", "POLICY", "OWNER"],
    ...rows.map((c) => [
      `${c.cid}${c.isDefault ? " *" : ""}`,
      c.name,
      c.frozen ? `${c.role} (frozen)` : c.role,
      `${c.standing}/${c.members}`,
      c.policy,
      c.ownerAddress,
    ]),
  ]);
}

export function formatMembers(r: { circle: CircleSummary; members: MemberRow[] }): string {
  const head = `${r.circle.name} (${r.circle.cid}), version ${r.circle.ver}, ${r.circle.policy}${r.circle.policy === "open" ? ": anyone with the link can join" : ""}`;
  return [
    head,
    table([
      ["MEMBER", "ROLE", "STANDING"],
      ...r.members.map((m) => [`${m.address}${m.self ? " (you)" : ""}`, m.owner ? "owner" : m.admin ? "admin" : "member", m.stands ? "stands" : m.statement === "leave" ? "left" : "not joined yet"]),
    ]),
  ].join("\n");
}

export function formatRoster(r: RosterView): string {
  const who = r.vis === "circle" ? `circle ${r.circleName ?? r.circle}${r.parts.length ? ` + ${r.parts.map((p) => p.address).join(", ")}` : ""}` : r.parts.length ? r.parts.map((p) => p.address).join(", ") : "nobody else (private)";
  return `session ${r.sid} [${r.ref}] v${r.ver}: shared with ${who}${r.openCircle ? "\n! this circle is open: anyone the owner admits sees this session" : ""}`;
}

export function formatJoin(r: JoinResult): string {
  const owner = r.ownershipChanged ? `owner ${r.ownerAddress} (founded by ${r.founder})` : `owner ${r.ownerAddress}`;
  switch (r.status) {
    case "joined":
      return `Joined "${r.name}" (${r.cid}), ${owner}.${r.confirmation === "owner-only" ? " Confirmed with the owner (no other member to ask)." : r.confirmation === "unconfirmed" ? " Joined without a second confirmation, as you chose." : " Confirmed with the owner and another member."}${r.openWarning ? "\nThis circle is open: anyone with its link can join." : ""}`;
    case "waiting":
      return `Asked ${r.asked.length || "the owner"} for "${r.name}"'s history; no answer yet. Run the same command again once they've been online (or wait with --wait <seconds>).`;
    case "unconfirmed":
      return `Couldn't confirm "${r.name}" with a second member. Run again with --yes to join anyway.`;
    case "already":
      return `You're already in "${r.name}" (${r.cid}).`;
    case "refused":
      return `Not joined "${r.name}" (${r.cid}): ${r.refused}.`;
  }
}

export function formatRotationPlan(p: RotationPlan): string {
  // A label from a version this device didn't publish is shown as such (pre-release re-review N2), and so is why a device is dropped.
  const dev = (d: { did: string; label: string; keyholder?: boolean; labelTrusted?: boolean; why?: string }) =>
    `  ${d.did}${d.label ? ` (${d.labelTrusted === false ? "unverified label: " : ""}${sanitizePeerText(d.label, 64)})` : ""}${d.keyholder ? ", key holder" : ""}${d.why ? `: DROPPED, ${d.why} (keep it with --keep ${d.did})` : ""}`;
  return [
    `${p.contest ? "Contesting a rotation you didn't publish: moving" : "Rotating"} ${p.address} to a new identity key ${p.newFingerprint} (§2.8).`,
    ...(p.backup ? [`Its backup phrase is in ${p.backup.file}.`] : []),
    p.follow.length ? `These devices get the rotation to follow (each follows only when you accept it there):\n${p.follow.map(dev).join("\n")}` : "No other device follows.",
    ...(p.excluded.length ? [`These devices do NOT follow (excluded):\n${p.excluded.map(dev).join("\n")}`] : []),
    `${plural(p.friends, "friend")} get a fresh invite (they approve it); ${plural(p.owned, "circle")} you own move to the new key; in ${plural(p.memberOf, "other circle")} the owner swaps you in.`,
    // pre-release re-review M1: friendships this device can't vouch for are invited only when the user says so.
    ...((p.friendsOptIn ?? []).length
      ? [
          `These friends are NOT invited unless you say so (a thief's device may have made them):\n${p.friendsOptIn
            .map((f) => `  ${sanitizePeerText(f.address ?? f.userId, 96)}: ${f.why}${f.invited ? " [INVITED: you chose to]" : ` (invite with --invite ${f.userId})`}`)
            .join("\n")}`,
        ]
      : []),
    "A lost or stolen device listed above must be dropped (--exclude <did>): it is revoked before any code goes out. Last, your old identity publishes a final version with no devices.",
  ].join("\n");
}

export function formatRotation(r: RotateResult): string {
  const lines = [`Your identity is now ${r.address} (was ${r.from}); old identity final version ${r.finalVer ?? "?"}.`];
  if (r.devices.followed.length) lines.push(`Followed: ${r.devices.followed.map((d) => d.label || d.did).join(", ")}.`);
  if (r.devices.offline.length) lines.push(`Didn't follow (re-link each with \`p2p link join <code> --rotated\`): ${r.devices.offline.map((d) => d.label || d.did).join(", ")}.`);
  lines.push(`Friends invited: ${r.friends.invited}${r.friends.failed.length ? `; not reached: ${r.friends.failed.length} (they can join a fresh code from you)` : ""}.`);
  for (const c of r.circles) lines.push(`  circle "${sanitizePeerText(c.name, 64)}" (${c.cid}): ${c.role === "owner" ? "handed to the new key" : "join sent to the owner"}${c.status === "done" ? "" : ` [${c.status}${c.reason ? `: ${c.reason}` : ""}]`}`);
  for (const p of r.proofs) lines.push(`Proof ${p.kind}: ${p.claim}. ${p.publish}`);
  if (r.backup) lines.push(`New backup phrase saved to ${r.backup.file}: copy it somewhere safe, then delete the file. The old phrase no longer works.`);
  return lines.join("\n");
}

// Everything but tab and newline that a terminal could act on: C0, DEL, C1
// (incl. 8-bit CSI/OSC), U+2028/9, format characters (bidi overrides), lone surrogates.
const TERMINAL_UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\p{Cf}]|\p{Cs}/gu;

/**
 * review M2: what any printer writes to a terminal. Strips escape sequences'
 * control characters (ESC, CSI, OSC, BEL, ...) and bidi/format characters,
 * keeping newlines and tabs. Applied to every human line and every
 * diagnostic, whatever its source (relay replies, core rejection messages,
 * peer text).
 */
export function safeTerminal(s: unknown): string {
  return String(s).replace(TERMINAL_UNSAFE, "");
}

/**
 * JSON for stdout (`--json`, `watch --jsonl`): the same data, with the
 * characters JSON.stringify leaves raw but a terminal could act on (DEL, C1,
 * U+2028/9, format characters) written as \u escapes.
 */
export function safeJson(v: unknown): string {
  return JSON.stringify(v).replace(/[\u007f-\u009f\u2028\u2029\p{Cf}]/gu, (c) =>
    c
      .split("")
      .map((u) => `\\u${u.charCodeAt(0).toString(16).padStart(4, "0")}`)
      .join(""),
  );
}

/** Message text for a terminal: one sanitizer, a generous cap. */
export function terminalText(s: string): string {
  return sanitizePeerText(s, 4000);
}
