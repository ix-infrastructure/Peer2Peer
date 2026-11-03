// Copyright 2026 Ix Infrastructure Inc.
//
// Human output for a terminal (stdout a TTY, no --json): aligned tables,
// colour for state, relative times, names first with the fingerprint dimmed,
// headings and empty states that say what to do next. Piped or redirected
// output keeps format.ts's plain text, unchanged.
//
// Every string from a peer, a relay or the store goes through the TUI's
// sanitiser (clean/cell) before it is laid out, and safePretty() then removes
// anything a terminal could act on except the SGR colour codes made here.
// NO_COLOR, TERM=dumb (and FORCE_COLOR) decide `color` (tui/terminal.ts colorWanted).

import { COLOR, PLAIN, type Style } from "./prompt/picker.js";
import { cell, clean, displayWidth } from "./tui/sanitize.js";
import type { CircleSummary } from "./circle-ops.js";
import type { CodeRow, InviteCodeResult } from "./codes.js";
import type { DoctorResult } from "./doctor.js";
import type { PeerRow } from "./sessions.js";
import type { FriendRow } from "./social.js";

export interface Pretty {
  color: boolean;
  cols: number;
  /** Unix seconds (tests pin it). */
  now?: number;
}

const styleOf = (p: Pretty): Style => (p.color ? COLOR : PLAIN);
const nowOf = (p: Pretty) => p.now ?? Date.now() / 1000;

/** Everything a terminal could act on, except the SGR (colour) sequences this module writes. */
export function safePretty(s: string): string {
  return s
    .replace(/\u001b(?!\[[0-9;]*m)/g, "")
    .replace(/[\u0000-\u0008\u000b-\u001a\u001c-\u001f\u007f-\u009f\u2028\u2029]/g, "")
    .replace(/\p{Cf}/gu, "");
}

/** "2m ago", "3h ago", "just now"; "in 4d" for the future. */
export function ago(sec: number, now: number): string {
  const d = Math.round(now - sec);
  const f = (x: number) => (x < 60 ? `${x}s` : x < 3600 ? `${Math.floor(x / 60)}m` : x < 86_400 ? `${Math.floor(x / 3600)}h` : `${Math.floor(x / 86_400)}d`);
  if (d < 0) return `in ${f(-d)}`;
  return d < 5 ? "just now" : `${f(d)} ago`;
}

/** `name@fp`: the name first (bold), the fingerprint dimmed. */
export function who(address: string, st: Style, width = 48): string {
  const a = cell(address, width);
  const at = a.lastIndexOf("@");
  return at > 0 ? `${st.bold(a.slice(0, at))}${st.dim(a.slice(at))}` : st.bold(a);
}

type Cell = { text: string; style?: (s: string) => string; raw?: string };

/** An aligned table: `head` dimmed, widths by display width, the last column never padded. */
function table(head: string[], rows: Cell[][], st: Style): string {
  const width = (c: Cell) => displayWidth(c.text);
  const cols = head.map((h, i) => Math.max(displayWidth(h), ...rows.map((r) => (r[i] ? width(r[i]) : 0))));
  const line = (cells: Cell[]) =>
    cells
      .map((c, i) => {
        const shown = c.raw ?? (c.style ? c.style(c.text) : c.text);
        return i === cells.length - 1 ? shown : shown + " ".repeat(Math.max(0, cols[i] - width(c)));
      })
      .join("  ")
      .trimEnd();
  return [st.dim(line(head.map((h) => ({ text: h })))), ...rows.map(line)].join("\n");
}

const t = (s: unknown, w = 60, style?: (s: string) => string): Cell => ({ text: cell(s, w), ...(style ? { style } : {}) });
const name = (address: string, st: Style): Cell => {
  const a = cell(address, 48);
  return { text: a, raw: who(a, st) };
};
const heading = (s: string, st: Style) => st.bold(s);

export function prettyPeers(rows: PeerRow[], relays: { failed: { url: string }[] } | undefined, p: Pretty): string {
  const st = styleOf(p);
  const out: string[] = [];
  if (rows.length === 0) out.push(`${heading("Sessions", st)}\n${st.dim("No live sessions yet. Friends' and circle-mates' sessions show up here once they post a status.")}\nInvite someone: ${st.cyan("p2p invite")}`);
  else {
    const now = nowOf(p);
    const state = (r: PeerRow) => (!r.live ? t("stale", 8, st.dim) : r.state === "busy" ? t("busy", 8, st.yellow) : t("idle", 8, st.green));
    out.push(heading(`Sessions (${rows.length})`, st));
    out.push(
      table(
        ["WHO", "SESSION", "STATE", "WHERE", "SEEN"],
        rows.map((r) => [
          r.self ? { text: cell(`you${r.thisDevice ? " (this device)" : ""}`, 24), style: st.bold } : name(r.address, st),
          t(`${clean(r.label)} [${clean(r.ref)}]`, 28),
          state(r),
          t([r.repo, r.branch].filter(Boolean).map(clean).join("@") || "-", 32, st.dim),
          t(ago(now - r.ageSec, now), 10, st.dim),
        ]),
        st,
      ),
    );
    const notes = rows.filter((r) => r.summary).map((r) => `  ${who(r.self ? "you" : r.address, st)} ${st.dim("·")} ${cell(r.summary, Math.max(20, p.cols - 30))}`);
    if (notes.length) out.push("", ...notes);
  }
  if (relays?.failed.length) out.push("", st.red(`! unreachable: ${relays.failed.map((f) => cell(f.url, 60)).join(", ")}`));
  return out.join("\n");
}

export function prettyFriends(r: { friends: FriendRow[]; invites: { outgoing: unknown[]; held: number }; blocked: { address: string }[] }, p: Pretty): string {
  const st = styleOf(p);
  const now = nowOf(p);
  const out: string[] = [heading(`Friends (${r.friends.length})`, st)];
  if (r.friends.length === 0) out.push(st.dim("No friends yet."), `Invite someone: ${st.cyan("p2p invite")} (pick circles, get a link to send)`);
  else
    out.push(
      table(
        ["FRIEND", "SINCE", "STATUS"],
        r.friends.map((f) => [name(f.address, st), t(ago(f.since, now), 12, st.dim), f.canMessage ? t("connected", 24, st.green) : t("waiting for their cap", 24, st.yellow)]),
        st,
      ),
    );
  if (r.invites.outgoing.length > 0) out.push("", st.dim(`${r.invites.outgoing.length} open invite${r.invites.outgoing.length === 1 ? "" : "s"} of yours, not yet accepted`));
  if (r.invites.held > 0) out.push("", st.yellow(`${r.invites.held} held item${r.invites.held === 1 ? "" : "s"} waiting for you: `) + st.cyan("p2p held"));
  if (r.blocked.length > 0) out.push("", st.dim(`blocked: ${r.blocked.map((b) => cell(b.address, 48)).join(", ")}`));
  return out.join("\n");
}

export function prettyCircles(rows: CircleSummary[], p: Pretty): string {
  const st = styleOf(p);
  if (rows.length === 0) return `${heading("Circles", st)}\n${st.dim("You're in no circles yet.")}\nMake one: ${st.cyan("p2p circle create <name>")}   or join one: ${st.cyan("p2p circle join <link>")}`;
  return [
    heading(`Circles (${rows.length})`, st),
    table(
      ["NAME", "ROLE", "MEMBERS", "POLICY", "OWNER", "ID"],
      rows.map((c) => [
        { text: cell(`${clean(c.name)}${c.isDefault ? " (default)" : ""}`, 32), style: c.isDefault ? st.cyan : st.bold },
        t(c.frozen ? `${c.role} (frozen)` : c.role, 18, c.frozen ? st.red : undefined),
        t(`${c.standing}/${c.members}`, 9),
        t(c.policy, 7, c.policy === "open" ? st.yellow : undefined),
        name(c.ownerAddress, st),
        t(c.cid, 40, st.dim),
      ]),
      st,
    ),
  ].join("\n");
}

export function prettyHeld(rows: { id: string; type: string; summary: string; address: string; at?: number }[], p: Pretty): string {
  const st = styleOf(p);
  if (rows.length === 0) return `${heading("Held", st)}\n${st.dim("Nothing is waiting for you.")}`;
  const now = nowOf(p);
  return [
    heading(`Held (${rows.length})`, st),
    table(
      ["ID", "FROM", "WHAT", "WHEN"],
      rows.map((h) => [t(h.id, 24, st.cyan), name(h.address, st), t(h.summary, Math.max(24, p.cols - 60)), t(h.at ? ago(h.at / 1000, now) : "-", 10, st.dim)]),
      st,
    ),
    "",
    st.dim("Act on one: ") + st.cyan("p2p held approve") + st.dim(" or ") + st.cyan("p2p held decline") + st.dim(" (with no id, you pick from the list)"),
  ].join("\n");
}

export function prettyCodes(rows: CodeRow[], p: Pretty): string {
  const st = styleOf(p);
  if (rows.length === 0) return `${heading("Invites", st)}\n${st.dim("No invite codes.")}\nMake one: ${st.cyan("p2p invite")}`;
  const now = nowOf(p);
  const status = (r: CodeRow): Cell => {
    switch (r.status) {
      case "open":
        return t(`open, ${daysLeft(r.exp, now)} left`, 24, st.green);
      case "taken":
        return t("taken, nobody joined yet", 28, st.yellow);
      case "redeemed":
        return { text: cell(`joined: ${clean(r.redeemedBy?.address ?? "?")}`, 56), raw: `${st.green("joined:")} ${who(r.redeemedBy?.address ?? "?", st)}` };
      case "evicted":
        return t("evicted by the relay: make a new one", 40, st.red);
      default:
        return t(r.status, 12, st.dim);
    }
  };
  return [
    heading(`Invites (${rows.length})`, st),
    table(
      ["CODE", "FOR", "JOINS", "STATUS"],
      rows.map((r) => [
        t(r.status === "open" || r.status === "taken" ? r.code : r.code.replace(/[^/]*$/, (c) => `${c.slice(0, 4)}…`), 44, st.dim),
        t(r.to ? clean(r.to.address) : (r.label ?? "anyone"), 28),
        t(r.circles.length ? r.circles.map((c) => clean(c.name)).join(", ") : "friend only", 32),
        status(r),
      ]),
      st,
    ),
    "",
    st.dim("Cancel one: ") + st.cyan("p2p invites revoke <code>"),
  ].join("\n");
}

/** Whole days left, rounded up: a 7-day code a few seconds old still says "7 days". */
export function daysLeft(exp: number, now: number): string {
  const d = Math.max(1, Math.ceil((exp - now - 60) / 86_400));
  return `${d} day${d === 1 ? "" : "s"}`;
}

export function prettyInvite(r: InviteCodeResult, p: Pretty): string {
  const st = styleOf(p);
  const now = nowOf(p);
  const join = `p2p join${r.privateRelay ? " --allow-private-relay" : ""} '${cell(r.web, 400)}'`;
  const what = r.circles.length ? `It makes them your friend and joins them to ${r.circles.map((c) => st.bold(`"${cell(c.name, 40)}"`)).join(", ")}.` : "It makes them your friend.";
  return [
    st.bold(`Your invite${r.label ? ` for ${cell(r.label, 40)}` : ""}`) + st.dim(`  (works once, for ${daysLeft(r.expiresAt, now)}${r.to ? `, only for ${cell(r.to.address, 48)}` : ""})`),
    "",
    `  ${st.cyan(st.bold(cell(r.web, 400)))}`,
    "",
    st.dim(`  or the code: ${cell(r.code, 200)}   (${join})`),
    "",
    what,
    st.yellow("Send it over a channel you trust: ") + "anyone who sees it first can use it. They see who it's from and say yes before anything happens.",
    "",
    st.bold("Send them this message") + st.dim(" (it says how to install Peer2Peer if they don't have it):"),
    "",
    ...r.message.split("\n").map((l) => `  ${cell(l, 400)}`),
    "",
    st.dim("Who joined: p2p invites · undo: p2p remove <user> · cancel: p2p invites revoke <code>"),
  ].join("\n");
}

export function prettyDoctor(r: DoctorResult, plain: string, p: Pretty): string {
  const st = styleOf(p);
  return plain
    .split("\n")
    .map((l, i) => {
      const s = cell(l, 400);
      if (i === 0) return st.bold(s);
      if (s.startsWith("✓")) return st.green("✓") + s.slice(1);
      if (s.startsWith("✗")) return st.red("✗") + s.slice(1);
      if (s.startsWith("?")) return st.yellow("?") + s.slice(1);
      if (/^\s+(fix|to tell):/.test(s)) return st.dim(s);
      return s;
    })
    .join("\n")
    .concat(r.summary.fail === 0 ? `\n${st.green("Everything checks out.")}` : "");
}

export function prettyRelays(r: { relays: string[] }, status: { connected: string[]; failed: { url: string; reason: string }[] } | undefined, p: Pretty): string {
  const st = styleOf(p);
  const rows = r.relays.map((u) => {
    const bad = status?.failed.find((f) => f.url === u);
    const ok = status?.connected.includes(u);
    return [t(u, 60, st.bold), bad ? t(`unreachable: ${clean(bad.reason)}`, 60, st.red) : ok ? t("reachable", 12, st.green) : t("not checked", 12, st.dim)];
  });
  return [heading(`Relays (${r.relays.length})`, st), table(["RELAY", "STATUS"], rows, st), "", st.dim("Add or remove: ") + st.cyan("p2p relays add <url>") + st.dim(" · ") + st.cyan("p2p relays remove <url>")].join("\n");
}

export function prettyTrust(r: { users: { userId: string; address: string; blocked: boolean }[]; circles: { cid: string; name?: string | null; joined: boolean; open: boolean; members: string[] }[] }, p: Pretty): string {
  const st = styleOf(p);
  if (r.users.length === 0 && r.circles.length === 0) return `${heading("Trusted", st)}\n${st.dim("Nobody is trusted.")}\nTrust someone (their messages reach a session without the hold): ${st.cyan("p2p trust add")}`;
  const rows: Cell[][] = [
    ...r.users.map((u) => [name(u.address, st), u.blocked ? t("blocked: not trusted", 24, st.red) : t("trusted", 12, st.green)]),
    ...r.circles.map((c) => [
      t(`circle ${clean(c.name ?? c.cid)}`, 40, st.bold),
      !c.joined ? t("not joined: nobody", 24, st.dim) : c.open ? t("open now: nobody", 24, st.yellow) : t(`${c.members.length} members`, 16, st.green),
    ]),
  ];
  return [heading("Trusted", st), table(["WHO", "STATUS"], rows, st)].join("\n");
}

export function prettyStatus(r: { status: { state: string }; delivered: unknown[]; failed: { address: string }[]; roster: { sid: string; vis: string; circleName?: string; circle?: string; parts: { address: string }[] } }, p: Pretty): string {
  const st = styleOf(p);
  const shared = r.roster.vis === "circle" ? `circle ${cell(r.roster.circleName ?? r.roster.circle, 40)}` : r.roster.parts.length ? r.roster.parts.map((x) => cell(x.address, 48)).join(", ") : "nobody else (private)";
  return [
    `${r.status.state === "busy" ? st.yellow("busy") : st.green("idle")} posted to ${st.bold(String(r.delivered.length))} peer${r.delivered.length === 1 ? "" : "s"}${r.failed.length ? st.red(`; ${r.failed.length} unreachable (${r.failed.map((f) => cell(f.address, 48)).join(", ")})`) : ""}`,
    st.dim(`session ${cell(r.roster.sid, 40)}: shared with ${shared}`),
  ].join("\n");
}

export interface HomeData {
  address?: string;
  relays: { url: string; ok: boolean }[];
  online: string[];
  friends: number;
  held: number;
}

export const HOME_COMMANDS: [string, string][] = [
  ["p2p invite", "invite someone (pick circles, get a link)"],
  ["p2p join <link>", "accept an invite someone sent you"],
  ["p2p ls", "live sessions of your friends and circles"],
  ["p2p held", "what is waiting for your yes"],
  ["p2p tui", "everything, full screen"],
];

/** `p2p` with no arguments, on a terminal. */
export function prettyHome(d: HomeData, p: Pretty): string {
  const st = styleOf(p);
  const out: string[] = [st.bold("Peer2Peer")];
  if (!d.address) {
    out.push("", "No identity on this device yet.", `  ${st.cyan("p2p setup")}            make one`, `  ${st.cyan("p2p join <link>")}      or join with a link someone sent you`);
    return out.join("\n");
  }
  out.push(`You are ${who(d.address, st)}`, "");
  const up = d.relays.filter((r) => r.ok).length;
  out.push(
    `${st.dim("relays ")}  ${up === d.relays.length ? st.green(`${up}/${d.relays.length} reachable`) : st.red(`${up}/${d.relays.length} reachable`)}${d.relays.filter((r) => !r.ok).length ? st.dim(` (down: ${d.relays.filter((r) => !r.ok).map((r) => cell(r.url, 48)).join(", ")})`) : ""}`,
    `${st.dim("friends")}  ${d.friends}${d.online.length ? `, ${st.green(`${d.online.length} online`)}: ${d.online.slice(0, 5).map((a) => who(a, st, 32)).join(", ")}${d.online.length > 5 ? st.dim(` +${d.online.length - 5}`) : ""}` : st.dim(", none online")}`,
    `${st.dim("held   ")}  ${d.held ? st.yellow(`${d.held} waiting for you`) + st.dim(" (p2p held)") : st.dim("nothing waiting")}`,
    "",
    st.bold("Try"),
  );
  const w = Math.max(...HOME_COMMANDS.map(([c]) => c.length));
  for (const [c, what] of HOME_COMMANDS) out.push(`  ${st.cyan(c.padEnd(w))}  ${st.dim(what)}`);
  out.push("", st.dim("All commands: p2p --help"));
  return out.join("\n");
}
