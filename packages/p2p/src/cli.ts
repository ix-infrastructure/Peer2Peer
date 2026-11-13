// Copyright 2026 Ix Infrastructure Inc.
//
// The `p2p` command line. Every command:
//   --json   prints exactly one JSON object on stdout and exits 0, or prints
//            `{error, reason, ...}` and exits 1;
//   default  prints readable text (diagnostics on stderr).
// `watch --jsonl` prints one JSON line per event instead (see watch.ts).
//
// Daemon-free: each command opens the stores, does its work and exits.

import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import type { Readable, Writable } from "node:stream";
import * as codex from "@peer2peer/codex-bridge";
import { Command, CommanderError, Option } from "commander";
import { App, type Io } from "./app.js";
import { defaultRelays, normalizeRelays, ownAgentsDeliver, ownAgentsDeliverFrom, ownDevicesDeliver, readFileConfig, resolveHome, updateFileConfigField, type Env, type FileConfig } from "./config.js";
import { receiptsSetting, sendReceipt } from "./receipts.js";
import * as trustOps from "./trust.js";
import { CliError, toErrorJson } from "./errors.js";
import * as fmt from "./format.js";
import { safeJson, safeTerminal } from "./format.js";
import * as circles from "./circle-ops.js";
import { registerExtensionCommands } from "./ext-host.js";
import { ExtensionRegistry, loadExtensions } from "./extensions.js";
import * as codes from "./codes.js";
import { parseShortCode } from "./shortcode.js";
import * as identity from "./identity.js";
import { receiving } from "./inbound.js";
import * as rotation from "./rotation.js";
import * as sessions from "./sessions.js";
import * as projects from "./projects.js";
import { isDid } from "@peer2peer/core/v3";
import * as ixLocal from "./ix-local.js";
import * as history from "./history.js";
import { confirmOnTty } from "./tty-confirm.js";
import * as social from "./social.js";
import { watch } from "./watch.js";
import * as doctorOps from "./doctor.js";
import { tuiCommand } from "./tui/command.js";
import { TUI_SESSION } from "./tui/tui.js";
import * as pretty from "./pretty.js";
import type { Choice, SelectSpec } from "./prompt/picker.js";
import type { Terminal } from "./tui/terminal.js";

import { VERSION } from "./version.js";
export { VERSION };

/** How long a command that ran out of time waits for in-flight sends and writes to settle. */
export const SETTLE_MS = 5000;

/** The operations the commands call: real modules by default, fakes in parser tests. */
export const realOps = { ...identity, ...social, ...circles, ...sessions, ...codes, ...rotation, ...projects, watch, doctor: doctorOps.doctor };
export type Ops = typeof realOps;

export interface ProgramDeps {
  env: Env;
  io: Io;
  ops?: Partial<Ops>;
  /** Builds the context (tests inject one). */
  makeApp?: (env: Env, io: Io, opts?: { readOnly?: boolean }) => App;
  /** Installed extensions (main() loads them; tests inject a registry). Absent: none. */
  extensions?: ExtensionRegistry;
  /** For `watch`. */
  signal?: AbortSignal;
  writeLine?: (line: string) => Promise<boolean>;
  /** `tui` (tests): a fake terminal instead of process.stdin/stdout. */
  terminal?: Terminal;
  /** `codex`: the running p2p script (default: process.argv[1]). */
  scriptPath?: string;
  /** `codex install`: the command that runs node in the printed config (default: `node`). */
  nodeCommand?: string;
  /** `codex mcp`: the MCP transport (default: process stdin/stdout). */
  stdin?: Readable;
  stdout?: Writable;
  /** `codex release|decline`: whether stdin and stdout are a real terminal (default: process.stdin/stdout). */
  isTTY?: boolean;
  /** `--no-input` (anywhere on the command line): no pickers and no questions, as in a script. */
  noInput?: boolean;
  /** The person token was valid (main() checks it once and removes it from the environment: projects.ts). */
  front?: boolean;
  /** The person's "yes" on their controlling terminal (tty-confirm.ts; tests stand in). */
  confirmTty?: projects.ConfirmTty;
}

interface Output {
  json: unknown;
  human: string;
  /** On a terminal (io.pretty): the same result laid out by pretty.ts. Piped output keeps `human`. */
  pretty?: (p: pretty.Pretty) => string;
}

const collect = (v: string, prev: string[] = []) => [...prev, v];

/**
 * Commands that widen who reaches this user: refused inside an agent's session unless the
 * person's front end passes its token (projects.ts assertPersonForWidening). Reads never are.
 */
const WIDENING = new Set(["project share", "circle default", "invite", "join", "accept", "trust add", "held approve", "circle invite", "circle join", "circle policy", "unblock", "link start", "link join", "identity follow", "extensions enable"]);

/** The widening command `cmd` is (its path from the program, with `session roster` only when it adds), or undefined. */
export function wideningOf(cmd: Command): string | undefined {
  const path: string[] = [];
  for (let c: Command | null = cmd; c && c.parent; c = c.parent) path.unshift(c.name());
  const p = path.join(" ");
  if (WIDENING.has(p)) return p;
  if (p === "session roster") {
    const o = cmd.opts() as { add?: string[]; circle?: string };
    if ((o.add?.length ?? 0) > 0 || o.circle !== undefined) return p;
  }
  return undefined;
}
const posInt = (name: string) => (v: string) => {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < 0) throw new CliError("usage", `${name} must be a non-negative integer`);
  return n;
};

export function buildProgram(deps: ProgramDeps): Command {
  const ops: Ops = { ...realOps, ...deps.ops } as Ops;
  const confirmTty: projects.ConfirmTty = deps.confirmTty ?? confirmOnTty;
  // review M2: every diagnostic goes through safeTerminal; human stdout too (below); JSON through safeJson.
  // Time spent waiting on the user (prompts, stdin) doesn't count against the command deadline.
  let waitingOnUser = 0;
  const onUser = <T>(f: () => Promise<T>) => async (): Promise<T> => {
    const t0 = Date.now();
    try {
      return await f();
    } finally {
      waitingOnUser += Date.now() - t0;
    }
  };
  // --no-input: no picker and no question at all (a script's behaviour, on a terminal too).
  const { select: rawSelect, prompt: rawPrompt, promptSecret: rawSecret, ...rest } = deps.io;
  const inIo: Io = deps.noInput ? rest : deps.io;
  const base: Io = { ...rest, out: (s) => deps.io.out(safeTerminal(s)), err: (s) => deps.io.err(safeTerminal(s)) };
  void rawSelect;
  void rawPrompt;
  void rawSecret;
  const io: Io = {
    ...base,
    ...(inIo.prompt ? { prompt: (q: string) => onUser(() => inIo.prompt!(q))() } : {}),
    ...(inIo.promptSecret ? { promptSecret: (q: string) => onUser(() => inIo.promptSecret!(q))() } : {}),
    ...(inIo.select ? { select: (s: SelectSpec) => onUser(() => inIo.select!(s))() } : {}),
    ...(deps.io.readStdin ? { readStdin: (o?: { implicit?: boolean }) => onUser(() => deps.io.readStdin!(o))() } : {}),
  };
  const extensions = deps.extensions ?? new ExtensionRegistry();
  const baseMakeApp = deps.makeApp ?? ((env, i, o) => new App({ env, io: i, ...(o?.readOnly ? { readOnly: true } : {}) }));
  // Every context renders inbound `x:<ns>.*` kinds with the installed extensions (extensions.ts).
  const makeApp = (env: Env, i: Io, o?: { readOnly?: boolean }): App => {
    const app = baseMakeApp(env, i, o);
    app.extensions ??= extensions;
    app.front = deps.front === true;
    app.confirmTty = confirmTty;
    return app;
  };
  const program = new Command("p2p")
    .description("Peer2Peer: an account-free network for AI agent sessions and the people who run them")
    .version(VERSION)
    .showHelpAfterError()
    .enablePositionalOptions()
    .exitOverride()
    .configureOutput({ writeOut: (s) => io.out(s.replace(/\n$/, "")), writeErr: (s) => io.err(s.replace(/\n$/, "")) });

  /** Runs one command: JSON or human output, exit code 1 on failure. */
  const run =
    <A extends unknown[]>(fn: (app: App, ...args: A) => Promise<Output>, opts: { requireIdentity?: boolean; noDeadline?: boolean; waitDefault?: number; sends?: boolean; readOnly?: boolean } = {}) =>
    async (...args: A) => {
      const cmd = args[args.length - 1] as Command;
      const json = Boolean(cmd.opts().json);
      const app = makeApp(deps.env, io, opts.readOnly ? { readOnly: true } : undefined);
      let stop = () => {};
      try {
        // §2.8 (L4): a follow that died mid-swap finishes before anything reads this home (not for a
        // read-only command, which must leave the home exactly as it found it).
        if (typeof app.home === "string" && !opts.readOnly) await rotation.recoverInterruptedFollow(app.home).catch(() => false);
        // An agent can't widen who reaches this user, however it runs p2p (projects.ts).
        const widening = wideningOf(cmd);
        if (widening) await projects.assertPersonForWidening(app, widening, confirmTty, undefined, { noTokenBeforeIdentity: widening === "link join" });
        if (opts.requireIdentity !== false) await app.load(true);
        // The person token the person's front ends pass back (projects.ts), made once, in the CLI's own folder.
        if (app.keys && !opts.readOnly && typeof app.home === "string") projects.personToken(app.home);
        if (app.keys) receiving(app);
        // The whole command is bounded (P2P_COMMAND_TIMEOUT_SEC, default 60 s, plus any --wait),
        // so it can't hang without a word: on expiry it fails naming the step it was on.
        const wait = cmd.opts().wait;
        const base = app.tun?.commandTimeoutSec ?? 0;
        const limitMs = opts.noDeadline || base <= 0 ? 0 : (base + (typeof wait === "number" ? wait : (opts.waitDefault ?? 0))) * 1000;
        const work = fn(app, ...args);
        let out: Output;
        if (limitMs > 0) {
          work.catch(() => {});
          const start = Date.now();
          const user0 = waitingOnUser;
          const expired = await Promise.race([
            work.then(
              (o) => ({ o }),
              (e: unknown) => ({ e }),
            ),
            new Promise<"expired">((resolve) => {
              const t = setInterval(() => {
                if (Date.now() - start - (waitingOnUser - user0) < limitMs) return;
                clearInterval(t);
                resolve("expired");
              }, 200);
              t.unref?.();
              stop = () => clearInterval(t);
            }),
          ]);
          if (expired !== "expired") {
            if ("e" in expired) throw expired.e;
            out = expired.o;
          } else {
            const at = app.progress?.current;
            // review L1: stop the work (no new network step starts), then let what is already on the
            // wire settle, bounded, before closing.
            app.abort?.abort();
            await Promise.race([work.catch(() => undefined), new Promise((r) => setTimeout(r, SETTLE_MS).unref())]);
            const secs = Math.round(limitMs / 1000);
            if (opts.sends) {
              throw new CliError(
                "outcome_unknown",
                `outcome unknown: it may have been delivered; check before resending (\`p2p ${cmd.name()}\` ran out of time after ${secs}s${at ? ` while ${at}` : ""})`,
              );
            }
            throw new CliError("timeout", `\`p2p ${cmd.name()}\` gave up after ${secs}s${at ? ` while ${at}` : ""}. Check your network and relays; P2P_DEBUG=1 shows each step`);
          }
        } else out = await work;
        if (json) io.out(safeJson(out.json));
        else if (deps.io.pretty && out.pretty) deps.io.out(pretty.safePretty(out.pretty(deps.io.pretty)));
        else if (out.human) io.out(safeTerminal(out.human));
        // Ix is optional: new installs are offered it; an existing one hears it once, at a terminal, from the person (ix-local.ts).
        if (!json && !opts.readOnly && app.keys && deps.io.prompt && projects.personHere(app) && cmd.name() !== "setup") {
          const n = await ixLocal.ixNotice(app).catch(() => undefined);
          if (n) io.err(`p2p: ${n}`);
        }
      } catch (e) {
        const j = toErrorJson(e);
        if (json) io.out(safeJson(j));
        else io.err(`p2p: ${String(j.error)}: ${String(j.reason)}`);
        process.exitCode = j.error === "restore_incomplete" ? 2 : 1;
      } finally {
        stop();
        await app.close().catch(() => {});
      }
    };

  const confirmPrompt = async (q: string, yes?: boolean, labels: [string, string] = ["Yes", "No"]): Promise<boolean> => {
    if (yes) return true;
    if (io.select) {
      // A picker: the question's last line is asked, the lines before it are shown above.
      const lines = q.split("\n");
      const r = await io.select({ intro: lines.slice(0, -1), message: lines[lines.length - 1] || "Continue?", choices: [{ value: "yes", label: labels[0] }, { value: "no", label: labels[1] }], initial: "no" });
      return r?.[0] === "yes";
    }
    if (!io.prompt) return false;
    const a = (await io.prompt(`${q} [y/N] `)).trim().toLowerCase();
    return a === "y" || a === "yes";
  };

  /** The command whose options `o` are (commander passes the same object it keeps). */
  const cmdOf = (o: object): Command => ({ opts: () => o }) as unknown as Command;
  // ── pickers (prompt/): only with io.select, never with --json or --yes ──
  const canAsk = (cmd: Command) => Boolean(io.select) && !cmd.opts().json && !cmd.opts().yes;
  const ask = async (spec: SelectSpec): Promise<string[]> => {
    const r = await io.select!(spec);
    if (r === undefined) throw new CliError("cancelled", "cancelled: nothing was done");
    return r;
  };
  const pickOne = async (message: string, choices: Choice[], empty: string): Promise<string> => {
    if (choices.length === 0) throw new CliError("usage", empty);
    return (await ask({ message, choices }))[0];
  };
  /**
   * A command whose positional arguments may be picked: without a picker (a script, a pipe, --json,
   * --no-input, CI), a missing one is the same commander error, help and exit code as before.
   */
  const pickable =
    <A extends unknown[]>(names: string[], action: (...args: A) => Promise<void>) =>
    async (...args: A) => {
      const cmd = args[args.length - 1] as Command;
      if (!canAsk(cmd)) {
        names.forEach((n, i) => {
          if (args[i] === undefined) cmd.error(`error: missing required argument '${n}'`, { code: "commander.missingArgument" });
        });
      }
      return action(...args);
    };
  const friendChoices = async (app: App): Promise<Choice[]> =>
    (await ops.friends(app)).friends.map((f) => ({ value: f.userId, label: f.address, detail: f.canMessage ? "connected" : "waiting for their cap" }));
  const circleChoices = async (app: App, which: (c: circles.CircleSummary) => boolean): Promise<Choice[]> =>
    (await ops.listCircles(app)).filter(which).map((c) => ({ value: c.cid, label: c.name, detail: `${fmt.plural(c.members, "member")} · ${c.policy} · ${c.role}${c.isDefault ? " · default" : ""}` }));
  const heldChoices = async (app: App): Promise<Choice[]> => (await ops.listHeld(app)).map((h) => ({ value: h.id, label: `${h.address}: ${h.summary}`, detail: h.type }));

  /** What `p2p join` says it did (setup's invite path says the same). */
  const joinLines = (r: Awaited<ReturnType<Ops["joinCode"]>>): string[] => {
    const lines = [`You and ${r.friend.address} are friends${r.delivered && r.delivered.relays.length === 0 ? " (they'll know once the accept is delivered: run this again later)" : ""}.`];
    for (const c of r.circles) {
      if (c.status === "joined" || c.status === "already") lines.push(`${c.status === "joined" ? "Joined" : "Already in"} "${c.name}"${c.default ? "; it is your default circle (new sessions start in it; running ones stay as they are)" : ""}.`);
      else if (c.status === "pending") lines.push(`${r.friend.address} adds you to "${c.name}" when their client next runs; your next p2p command finishes the join.`);
      else if (c.status === "held") lines.push(`Not joined "${c.name}" from this code (${c.reason}): if its invite comes, \`p2p held\` lists it for you to approve on its own.`);
      else lines.push(`"${c.name}" couldn't be confirmed with a second member (§3.3): \`p2p held approve ${c.held}\` to join anyway.`);
    }
    return lines;
  };

  // ── setup's questions (a person at a terminal only: io.prompt) ──
  /** One of `letters`, asked at most three times; then nothing is done. */
  const askLetter = async (q: string, letters: string[]): Promise<string> => {
    for (let i = 0; i < 3; i++) {
      const a = (await io.prompt!(q)).trim().toLowerCase();
      if (letters.includes(a)) return a;
      io.err(`Type ${letters.slice(0, -1).join(", ")} or ${letters[letters.length - 1]}.`);
    }
    throw new CliError("cancelled", "cancelled: nothing was done (run `p2p setup` again)");
  };
  const askNonEmpty = async (q: string, what: string): Promise<string> => {
    for (let i = 0; i < 3; i++) {
      const a = (await io.prompt!(q)).trim();
      if (a !== "") return a;
      io.err(`Type ${what}, or press Ctrl-C to stop.`);
    }
    throw new CliError("cancelled", "cancelled: nothing was done (run `p2p setup` again)");
  };
  /** How a person with no identity here is joining (setup): before any key is made. */
  const askJoinPath = async (p2p: string): Promise<"link" | "invite" | "new"> => {
    io.out(
      [
        "How are you joining Peer2Peer?",
        "  [l] I already use Peer2Peer on another device: link this device to it",
        "  [i] I have an invite link or code from someone",
        "  [n] Start a new identity (my first device)",
        `(Already have an identity? Choose l: a new one here would be a second, separate identity. ${p2p} link join and ${p2p} join do the same later.)`,
      ].join("\n"),
    );
    const a = await askLetter("Choose l, i or n: ", ["l", "i", "n"]);
    return a === "l" ? "link" : a === "i" ? "invite" : "new";
  };
  /** The group's relay for a new identity (no default relay: bring your own), as a canonical wss:// URL. */
  const askRelay = async (): Promise<string> => {
    io.out("\nPeer2Peer has no default relay: each group runs its own. Ask whoever runs yours for its address (wss://…).");
    for (let i = 0; i < 3; i++) {
      let a = (await io.prompt!("Relay URL (wss://…): ")).trim();
      // A bare host means wss:// (the only scheme a relay URL has); any other scheme is refused.
      if (a !== "" && !/^[a-z][a-z0-9+.-]*:\/\//i.test(a)) a = `wss://${a}`;
      if (!/^wss:\/\//i.test(a)) {
        io.err(a === "" ? "Type the relay's address (wss://…)." : "A relay URL starts with wss:// (ws://, http:// and https:// aren't relay URLs).");
        continue;
      }
      try {
        return normalizeRelays([a])[0];
      } catch (e) {
        io.err(e instanceof CliError ? String(e.message) : `${a} is not a relay URL`);
      }
    }
    throw new CliError("cancelled", "cancelled: nothing was done (run `p2p setup --relay wss://…` again)");
  };
  const isLinkCode = (s: string) => /^p2p-link:/i.test(s.trim());
  const looksLikeInvite = (s: string): boolean => {
    try {
      parseShortCode(s, { allowPrivate: true });
      return true;
    } catch {
      return false;
    }
  };
  /**
   * The person's yes, on their own terminal, to the identity a link code makes this device part of
   * (`link join` and setup's link path): nothing is kept before it.
   */
  const confirmLinkIdentity =
    (p2p: string) =>
    (who: identity.LinkIdentity): Promise<boolean> =>
      confirmTty(
        `This device would become ${who.address} (fingerprint ${who.fingerprint})${who.keyholder ? ", a key holder" : ""}. Is this your identity? It must match \`${p2p} whoami\` on your other device: a link code from anyone else makes this device theirs.`,
      );
  /** setup, "I already use Peer2Peer on another device": `p2p link join`, inline. No identity is made here, so no backup is asked. */
  const setupByLink = async (app: App, p2p: string, o: { allowPrivateRelay?: boolean; ignored: string[] }): Promise<Output | { invite: string }> => {
    await projects.assertPersonForWidening(app, "link join", confirmTty, undefined, { noTokenBeforeIdentity: true });
    io.out(
      [
        "",
        "Link this device to the identity you already have:",
        "  1. On your other device run:  p2p link start",
        "     (Windows PowerShell: p2p.cmd link start; in Claude Code: /peers link start)",
        "  2. It shows a one-time link code (p2p-link:…). Type it here.",
        "Only type a code shown on YOUR OWN other device. A code from anyone else makes this device theirs.",
        ...(o.ignored.length > 0 ? [`(${o.ignored.join(", ")} ${o.ignored.length === 1 ? "is" : "are"} ignored when linking: this device takes your identity's name, relays and backup.)`] : []),
      ].join("\n"),
    );
    const code = await askNonEmpty("Link code: ", "the link code");
    // An invite pasted here (someone else's): it is joined as an invite, with its own confirmation.
    if (!isLinkCode(code) && looksLikeInvite(code)) {
      io.err("That is an invite from someone, not a link code from your own device: joining with it as an invite instead (you'll see who it's from first).");
      return { invite: code };
    }
    const j = await ops.linkJoin(app, code, { ...(o.allowPrivateRelay ? { allowPrivateRelay: true } : {}) });
    io.out(`Compare code: ${j.compareCode}\nCheck the other device shows the same code, and confirm there. Waiting…`);
    const r = await j.wait(confirmLinkIdentity(p2p));
    return {
      json: { linked: r },
      human: [`This device is now ${r.address} (${r.did})${r.keyholder ? ", a key holder" : ""}.`, "", `Check it: ${p2p} whoami    Invite someone: ${p2p} invite <their name>`].join("\n"),
    };
  };

  // ── identity ──────────────────────────────────────────────────────────────
  program
    .command("init")
    .description("Create your identity key and first device, and publish your identity document")
    .option("--name <name>", "Your display name ([a-z0-9._-], not unique)")
    .option("--relay <url>", "A relay to use (repeat for up to 5); default: P2P_DEFAULT_RELAYS or config.json", collect)
    .option("-y, --yes", "Don't prompt about the backup (scripts); still prints a warning")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, o: { name?: string; relay?: string[]; yes?: boolean; json?: boolean }) => {
          if (!o.yes && !io.prompt) throw new CliError("usage", "init asks about a backup: run it in a terminal, or pass --yes in scripts");
          const r = await ops.init(app, { name: o.name, relays: o.relay });
          const lines = [
            `Created ${r.address}`,
            `  userId  ${r.userId}`,
            `  device  ${r.did} (key holder)`,
            `  ${r.published.length > 0 ? `published to ${fmt.plural(r.published.length, "relay")}: ${r.published.join(", ")}` : "not published yet: no relay answered (it will be retried)"}`,
          ];
          const warn =
            "Only this device holds your identity key. If you lose it without a backup, the identity is gone for good (§2.5).";
          let backup: string | undefined;
          if (o.yes) {
            io.err(`warning: ${warn} Run \`p2p backup show\` or link a second key holder.`);
          } else {
            io.out(lines.join("\n"));
            lines.length = 0;
            io.out(`\n${warn}\n  [b] show a 24-word backup phrase now (recommended)\n  [l] I'll link a second key-holding device (p2p link start --keyholder)\n  [s] skip for now`);
            const a = (await io.prompt!("Choose b, l or s: ")).trim().toLowerCase();
            if (a === "b" || a === "") {
              backup = (await ops.backupShow(app)).phrase;
              io.out(`\nWrite these 24 words down and keep them offline. Anyone with them is you:\n\n${backup}\n`);
            } else if (a === "l") io.out("Run `p2p link start --keyholder` on this device when the other one is ready.");
            else io.err(`warning: ${warn}`);
          }
          return { json: { ...r, backupShown: backup !== undefined }, human: lines.join("\n") };
        },
        { requireIdentity: false },
      ),
    );

  program
    .command("setup")
    .description("Get started: link this device to your identity, join with an invite, or create a new identity (safe to run again)")
    .option("--name <name>", "Your display name (default: your OS user name)")
    .option("--relay <url>", "A relay to use (repeat for up to 5); default: P2P_DEFAULT_RELAYS, config.json, or the relays shipped with the CLI", collect)
    .option("--backup-file [path]", "Save the 24-word backup phrase to a 0600 file (default <home>/backup-phrase.txt)")
    .option("--print-backup", "Print the backup phrase (in --json, as backup.phrase)")
    .option("--no-backup", "Don't save or print the backup phrase now")
    .option("--ix", "Offer Ix again after an earlier no (optional; Peer2Peer never installs it), and with Ix installed, offer to turn on the Ix extension")
    .option("--allow-private-relay", "Linking or joining: accept a code whose relay is a loopback, link-local or private address (your own relay on your network; also P2P_ALLOW_PRIVATE_RELAY=1)")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, o: { name?: string; relay?: string[]; backupFile?: string | true; printBackup?: boolean; backup?: boolean; ix?: boolean; allowPrivateRelay?: boolean; json?: boolean }) => {
          let mode: identity.BackupMode | undefined = o.backupFile !== undefined ? "file" : o.printBackup ? "print" : o.backup === false ? "none" : undefined;
          const existed = await app.load(false);
          const p2p = identity.p2pCommand();
          // Asked only once an identity exists here (its key was just made): never before.
          const askBackup = async (): Promise<identity.BackupMode> => {
            io.out(`\nYour identity key lives only on this device. A 24-word backup phrase restores it if the device is lost.\n  [f] save it to a file only you can read (0600), on this device: copy it off later\n  [p] print it now, for a password manager or paper (best)\n  [s] skip for now (${p2p} backup show later)`);
            const a = (await io.prompt!("Choose f, p or s: ")).trim().toLowerCase();
            return a === "p" ? "print" : a === "s" ? "none" : "file";
          };
          // A person at a terminal with no identity here says how they're joining first, before any key
          // is made: someone who already has an identity links this device to it instead of making a
          // second one. Never with --json, in CI, without a terminal, or inside an agent's session.
          const asking = !existed && !o.json && Boolean(io.prompt) && !ixLocal.ciEnv(app.env) && projects.personHere(app);
          let how = asking ? await askJoinPath(p2p) : "new";
          let inviteCode: string | undefined;
          if (how === "link") {
            const ignored = [
              ...(o.name !== undefined ? ["--name"] : []),
              ...(o.relay && o.relay.length > 0 ? ["--relay"] : []),
              ...(o.backupFile !== undefined ? ["--backup-file"] : []),
              ...(o.printBackup ? ["--print-backup"] : []),
            ];
            const l = await setupByLink(app, p2p, { allowPrivateRelay: o.allowPrivateRelay, ignored });
            if (!("invite" in l)) return l;
            how = "invite";
            inviteCode = l.invite;
          }
          let createdHere = false;
          if (how === "invite") {
            await projects.assertPersonForWidening(app, "join", confirmTty, undefined, { noTokenBeforeIdentity: true });
            if (inviteCode === undefined) io.out("\nPaste the invite link (https://…/p2p/invite#…) or the code you were sent. It carries the relays your inviter uses.");
            const code = inviteCode ?? (await askNonEmpty("Invite link or code: ", "an invite link or code"));
            if (isLinkCode(code)) {
              throw new CliError(
                "usage",
                `that is a device link code, not an invite: nothing was done. Link codes come only from your own other device, and one from anyone else makes this device theirs. If it is from your own device, run \`${p2p} setup\` again and choose l`,
              );
            }
            const j = await ops.joinCode(app, code, {
              name: o.name,
              ...(o.allowPrivateRelay ? { allowPrivateRelay: true } : {}),
              confirm: (q) => confirmPrompt(q, false, ["Join", "Cancel"]),
              create: async (a, x) => {
                const c = await ops.init(a, x);
                receiving(a);
                createdHere = true;
                io.out(`Created ${c.address}`);
                io.err(`Only this device holds your identity key: save a backup with \`${p2p} backup show\` (setup asks next).`);
                return { userId: c.userId, address: c.address, relays: c.relays };
              },
            });
            io.out(joinLines(j).join("\n"));
            if (createdHere && mode === undefined) mode = await askBackup();
          }
          let relays = o.relay;
          // There is no default relay (bring your own): a new identity starts on the group's relay.
          if (how === "new" && asking && !(relays && relays.length > 0) && defaultRelays(app.env, app.file).length === 0) relays = [await askRelay()];
          const chooseBackup =
            how === "new" && mode === undefined && !o.json && io.prompt
              ? async (c: identity.InitResult) => {
                  createdHere = true;
                  io.out(`Created ${c.address}`);
                  return askBackup();
                }
              : undefined;
          const r = await ops.setup(app, {
            name: o.name,
            relays,
            backup: mode,
            ...(typeof o.backupFile === "string" ? { backupFile: o.backupFile } : {}),
            ...(o.ix ? { ix: true } : {}),
            ...(chooseBackup ? { chooseBackup } : {}),
          });
          const lines = [...(createdHere ? [`Your identity: ${r.address}`] : [r.created ? `Created ${r.address}` : `Already set up: ${r.address}`]), `  relays  ${r.relays.join(", ")}`];
          if (r.backup?.file) {
            lines.push(`  backup  saved to ${r.backup.file}`);
            // review L4: the default file sits next to the key it backs up.
            io.err(
              `warning: the backup file is on this same device, so it doesn't protect you if the device is lost. Put the 24 words in a password manager (or on paper), then delete ${r.backup.file}.`,
            );
          }
          if (r.backup?.phrase) lines.push(`\nWrite these 24 words down and keep them offline. Anyone with them is you:\n\n${r.backup.phrase}\n`);
          // Whenever this device is the only key holder and the phrase was never shown (not only just
          // after creating it: a setup cut short at the question, or a join that failed after creating).
          if (r.backupNeeded) io.err(`warning: no backup yet: this device is the only one holding your identity key, so if you lose it, the identity is gone. Run \`${p2p} backup show\`.`);
          // Ix is optional and recommended: offered to the person at a terminal (default No), never
          // installed. Never with --json, in CI, without a terminal, or inside an agent's session.
          const offerIx =
            r.ix !== undefined && !r.ix.found && r.ix.recommended && !o.json && Boolean(io.prompt || io.select) && !ixLocal.ciEnv(app.env) && projects.personHere(app);
          if (r.ix?.enabledNow) lines.push("  ix      Ix found: the Ix extension is on (`p2p extensions disable ix` turns it off). Ix calls stay on this machine (graph: local only)");
          else if (r.ix?.enabled) lines.push("  ix      the Ix extension is on (graph: local only)");
          else if (r.ix?.hint && !offerIx) lines.push(`  ix      ${r.ix.hint}`);
          if (offerIx) {
            io.out(lines.join("\n"));
            lines.length = 0;
            const yes = await confirmPrompt(["", ...ixLocal.IX_PITCH, "Install Ix?"].join("\n"));
            if (yes) {
              if (ixLocal.ixDeclined(app.file)) ixLocal.setIxDeclined(app.home, false);
              // Printed, never run: installing is the person's own action, in their own terminal.
              lines.push(
                "",
                "Peer2Peer doesn't run installers. To install Ix, run this in your terminal:",
                "",
                ...ixLocal.ixInstallCommands().map((c) => `    ${c}`),
                "",
                `(details: ${ixLocal.IX_INSTALL_URL}). Then run \`p2p setup --ix\` to turn on the Ix extension.`,
              );
            } else {
              ixLocal.setIxDeclined(app.home, true);
              lines.push("  ix      not installing Ix. You won't be asked again; `p2p setup --ix` offers it again");
            }
          }
          lines.push("", "Invite someone: p2p invite <their name>    Join with a code: p2p join <code>");
          return { json: r, human: lines.join("\n") };
        },
        // review L1: never cut short half-way through creating an identity (each step is still bounded).
        { requireIdentity: false, noDeadline: true },
      ),
    );


  program
    .command("whoami")
    .description("Your address, fingerprint, devices, relays and document expiry")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await ops.whoami(app);
        return { json: r, human: fmt.formatWhoami(r) };
      }),
    );

  const backup = program.command("backup").description("The 24-word backup phrase of your identity key (§2.7)");
  backup
    .command("show")
    .description("Show the backup phrase (key-holding devices only)")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await ops.backupShow(app);
        return { json: r, human: `Keep these 24 words offline. Anyone who has them can act as you:\n\n${r.phrase}` };
      }),
    );
  backup
    .command("restore")
    .description("Restore your identity on this (fresh) device from the backup phrase")
    .option("--relay <url>", "A relay your identity uses (repeatable)", collect)
    .option("--name <name>", "Change your display name")
    .option("--keep-devices", "Keep your other devices listed (default: revoke them, as lost)")
    .option("--new-chain", "When the relays hold no document for this identity, start a new history at version 1")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, o: { relay?: string[]; name?: string; keepDevices?: boolean; newChain?: boolean }) => {
          // review L4: never on the command line (argv is visible to other local users and shell history).
          let phrase: string | undefined;
          if (io.promptSecret) phrase = await io.promptSecret("Backup phrase (24 words, not shown): ");
          else if (io.prompt) throw new CliError("usage", "this terminal can't hide input: pipe the phrase on stdin instead");
          else if (io.readStdin) phrase = await io.readStdin();
          if (!phrase?.trim()) throw new CliError("usage", "type the phrase when asked, or pipe it on stdin");
          const r = await ops.backupRestore(app, phrase, { relays: o.relay, name: o.name, keepDevices: o.keepDevices, newChain: o.newChain });
          // R4-M2: committed locally, but some listed relay refused: a distinct error (exit 2), with the full result.
          if ((r.failed ?? []).length > 0) {
            throw new CliError("restore_incomplete", `restored locally, but ${r.failed.length} relay(s) didn't take the new document: run \`p2p identity republish\``, { ...r });
          }
          return {
            json: r,
            human: `Restored ${r.address} on this device (${r.did}), document version ${r.ver}.${r.revoked.length ? `\nRevoked ${fmt.plural(r.revoked.length, "old device")}.` : ""}\nFriendships aren't in the phrase: invite your friends again.`,
          };
        },
        // review L1: a restore is never cut short by the command deadline (each step is still bounded).
        { requireIdentity: false, noDeadline: true },
      ),
    );

  const relays = program
    .command("relays")
    .description("The relays your identity document lists; `relays add|remove <url>` publishes the next version")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await ops.relaysList(app);
        // On a terminal: each relay's health too (a bounded connect; piped output stays the plain list).
        if (io.pretty) await app.connect({ allowNone: true }).catch(() => undefined);
        return { json: r, human: r.relays.join("\n"), pretty: (p) => pretty.prettyRelays(r, app.relayStatus, p) };
      }),
    );
  for (const verb of ["add", "remove"] as const) {
    relays
      .command(`${verb} <url>`)
      .description(verb === "add" ? "Add a relay (1-5 in all)" : "Remove a relay (one must stay)")
      .option("--json", "JSON output")
      .action(
        run(async (app, url: string) => {
          const r = verb === "add" ? await ops.relaysAdd(app, url) : await ops.relaysRemove(app, url);
          const failed = r.failed.length ? `; not yet on ${r.failed.map((f) => f.relay).join(", ")} (retried later)` : "";
          return { json: r, human: `Your relays (document version ${r.ver}): ${r.relays.join(", ")}${failed}.` };
        }),
      );
  }

  const ident = program.command("identity").description("Your identity document");
  ident
    .command("republish")
    .description("Publish your current identity document again to every relay it lists (after a restore, or a relay that was down)")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await app.republish();
        if (r.failed.length > 0) throw new CliError("not_published", `${r.failed.length} relay(s) still refused: ${r.failed.map((f) => `${f.relay}: ${f.code}`).join(", ")}`, { ...r });
        return { json: r, human: `Version ${r.ver} is on ${fmt.plural(r.ok.length, "relay")}: ${r.ok.join(", ")}.` };
      }),
    );

  ident
    .command("rotate")
    .description("Move to a new identity key: the remedy for a lost or stolen key-holding device (§2.8)")
    .option("--plan", "Make the new key and show the plan (its fingerprint, which devices would follow); publish nothing")
    .option("--resume", "Accept a plan made with --plan, or finish a rotation that was interrupted")
    .option("--cancel", "Drop a plan that wasn't accepted (nothing was published)")
    .option("--exclude <did>", "A device that must NOT follow (the lost or stolen one): revoked first; repeatable", collect)
    .option("--keep <did>", "Let a device the plan dropped by default follow anyway (added by a version you didn't publish, or not seen lately); repeatable", collect)
    .option("--invite <user>", "Invite a friend the plan leaves out by default (a friendship made by a device it drops, or one that doesn't verify now); repeatable", collect)
    .option("--keep-keyholders", "Devices that held the old identity key also get the new one (default: they follow as ordinary devices)")
    .option("--wait <seconds>", "How long to wait for your other devices to follow (default 600, the link code's life)", posInt("--wait"))
    .option("--backup-file [path]", "Save the new key's 24-word backup phrase to a 0600 file (default <home>/backup-phrase-<fingerprint>.txt)")
    .option("--contest", "On a key holder: answer a rotation of your identity this device didn't publish with a competing one, so your friends see a conflict and apply neither")
    .option("--resend", "After a rotation: send the new identity's invite again to the friends it didn't reach (throttled)")
    .option("-y, --yes", "Accept the plan without asking (scripts)")
    .option("--json", "JSON output")
    .addHelpText(
      "after",
      [
        "",
        "What happens: a new identity key and device keys for this device; the plan (the new fingerprint, the devices",
        "that would follow: drop a lost one with --exclude, it is revoked first) for you to accept; a statement signed",
        "by the old and the new key; the new identity is published on your relays; each other device gets a held",
        "rotation it follows only when you say so there (`p2p identity follow <id>`; an offline one re-links later with",
        "`p2p link join <code> --rotated`); every friend gets a fresh invite they approve as \"<you> moved to a new key\";",
        "circles you own are handed to the new key and circles you are in get your new identity's join; proofs are",
        "re-signed (update the gist or DNS record it prints). Last, once the new key has a backup (--backup-file) or a",
        "key-holding device followed (--keep-keyholders), the old identity publishes a final version with no devices:",
        "relays then refuse its devices.",
        "",
        "Security: someone who also has your old identity key can publish a competing rotation. Your devices alert;",
        "a key holder contests it (--contest). Your friends then see a conflict and nothing is applied: they check with",
        "you out of band (petnames, proofs) and exchange a fresh invite. Friends act only on a rotation the old",
        "identity's own final version carries. Rotation can't recover circles whose owner key was compromised:",
        "re-create those (§3.3).",
      ].join("\n"),
    )
    .action(
      run(
        async (
          app,
          o: { plan?: boolean; resume?: boolean; cancel?: boolean; exclude?: string[]; keep?: string[]; invite?: string[]; keepKeyholders?: boolean; wait?: number; backupFile?: string | true; contest?: boolean; resend?: boolean; yes?: boolean; json?: boolean },
        ) => {
          const backupFile = o.backupFile === undefined ? undefined : typeof o.backupFile === "string" ? o.backupFile : true;
          const backup = backupFile === true ? { backupFileDefault: true } : backupFile ? { backupFile } : {};
          if (o.cancel) {
            const r = await ops.rotateCancel(app);
            return { json: r, human: r.cancelled ? "Dropped the rotation plan: nothing was published." : "No rotation plan to drop." };
          }
          if (o.resend) {
            const r = await ops.rotateResend(app);
            return {
              json: r,
              human: `Sent your new identity's invite to ${fmt.plural(r.sent, "friend")}${r.failed.length ? `; ${r.failed.length} still not reached` : ""}${r.throttled ? ` (${r.remaining} wait for the relays' hourly limit: run it again later)` : ""}.`,
            };
          }
          const opts = { resume: o.resume, exclude: o.exclude, keep: o.keep, invite: o.invite, keepKeyholders: o.keepKeyholders, contest: o.contest, ...backup };
          if (o.plan) {
            const plan = await ops.rotatePlan(app, opts);
            return { json: { plan: true, ...plan }, human: `${fmt.formatRotationPlan(plan)}\nAccept it with \`p2p identity rotate --resume\` (add --exclude <did> to drop a device), or drop it with --cancel.` };
          }
          const r = await ops.rotate(app, {
            ...opts,
            waitSec: o.wait,
            yes: o.yes,
            ...(io.prompt
              ? {
                  confirm: async (plan: Parameters<typeof fmt.formatRotationPlan>[0]) => {
                    // Never on stdout with --json: that carries exactly one JSON object.
                    (o.json ? io.err : io.out)(fmt.formatRotationPlan(plan));
                    return confirmPrompt("Rotate your identity to this new key?");
                  },
                }
              : {}),
          });
          return { json: r, human: fmt.formatRotation(r) };
        },
        { requireIdentity: false },
      ),
    );

  ident
    .command("dispute <id>")
    .description("Settle a contested move to a new key (§2.8): keep the identity that is really them, or neither")
    .option("--keep <user>", "The new identity you confirmed out of band")
    .option("--neither", "Keep neither (both stay suspended)")
    .option("--json", "JSON output")
    .action(
      run(async (app, id: string, o: { keep?: string; neither?: boolean }) => {
        if (!!o.keep === !!o.neither) throw new CliError("usage", "give exactly one of --keep <user> or --neither");
        const r = await ops.resolveDispute(app, id, { keep: o.keep, neither: o.neither });
        return { json: r, human: r.keep ? `Kept ${await app.addressOf(String(r.keep))}; the other${(r.rejected as string[]).length === 1 ? "" : "s"} stay suspended.` : "Kept neither: all of them stay suspended." };
      }),
    );

  ident
    .command("follow <id>")
    .description("On this (not key-holding) device: follow a rotation of your identity that one of your key holders started (§2.8)")
    .option("--json", "JSON output")
    .action(
      run(async (app, id: string) => {
        const r = await ops.followHeld(app, id);
        return { json: r, human: `This device moved with your identity: it is now ${r.address} (${r.did}).` };
      }),
    );

  const link = program.command("link").description("Link another device to your identity (§2.4)");
  link
    .command("start")
    .description("On a key-holding device: show a one-time link code for the new device")
    .option("--keyholder", "Make the new device key-holding (it gets your identity key)")
    .option("--relay <url>", "Relay for the link mailbox (default: your first relay)")
    .option("--expect-compare <code>", "Proceed only if the answering device's compare code is this (for scripts; read it off the new device)")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { keyholder?: boolean; relay?: string; expectCompare?: string; json?: boolean }) => {
        // review N-M1: never accept whichever device answers first. Without a terminal to ask, the
        // expected compare code must be given.
        const expect = o.expectCompare?.trim().toLowerCase();
        if (expect === undefined && !io.prompt) throw new CliError("usage", "link start confirms the compare code: run it in a terminal, or pass --expect-compare <code>");
        const s = await ops.linkStart(app, { keyholder: o.keyholder, relay: o.relay });
        if (o.json) io.err(JSON.stringify({ event: "code", code: s.code, relay: s.relay, expiresAt: s.expiresAt }));
        else {
          io.out(`On the new device run:\n\n  p2p link join ${s.code}\n`);
          const code = fmt.qr(s.code);
          if (code) io.out(code);
          io.out("Show this only on a screen you control: never paste it into a chat or a screen share. It works once, for 10 minutes.\nWaiting for the new device…");
        }
        let shown = "";
        const r = await s.wait(async (req) => {
          shown = req.compareCode;
          if (o.json) io.err(JSON.stringify({ event: "answered", label: req.label, compareCode: req.compareCode, did: req.did }));
          else io.out(`\nA device "${req.label}" answered. Its compare code: ${req.compareCode}`);
          if (expect !== undefined) return req.compareCode.toLowerCase() === expect;
          return confirmPrompt(`Does the new device show ${req.compareCode}?`);
        });
        return { json: { ...r, compareCode: shown }, human: `Linked ${r.did}${r.label ? ` (${r.label})` : ""}${r.keyholder ? " as a key holder" : ""}; your document is now version ${r.ver}.` };
      }, { noDeadline: true }),
    );
  link
    .command("join <code>")
    .description("On the new device: join with the code the other device shows")
    .option("--label <label>", "A name for this device")
    .option("--rotated", "This device's identity was rotated while it was offline: re-link it to the new identity (§2.8)")
    .option("--expect-fingerprint <fingerprint>", "Proceed only if the identity is this one (for scripts; `p2p whoami` on the other device shows it); otherwise you confirm it on your terminal")
    .option("--allow-private-relay", "Accept a code whose relay is a loopback, link-local or private address (your own relay on your network; also P2P_ALLOW_PRIVATE_RELAY=1)")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, code: string, o: { label?: string; rotated?: boolean; expectFingerprint?: string; allowPrivateRelay?: boolean; json?: boolean }) => {
          if (o.rotated) {
            const j = await ops.relinkRotated(app, code, { label: o.label });
            if (o.json) io.err(JSON.stringify({ compareCode: j.compareCode, did: j.did }));
            else io.out(`Compare code: ${j.compareCode}\nCheck the other device shows the same code, and confirm there. Waiting…`);
            const r = await j.wait();
            return { json: r, human: `This device is now ${r.address} (${r.did})${r.keyholder ? ", a key holder" : ""}.` };
          }
          const j = await ops.linkJoin(app, code, { label: o.label, ...(o.allowPrivateRelay ? { allowPrivateRelay: true } : {}) });
          if (o.json) io.err(JSON.stringify({ compareCode: j.compareCode, did: j.did }));
          else io.out(`Compare code: ${j.compareCode}\nCheck the other device shows the same code, and confirm there. Waiting…`);
          // Which identity this device becomes is the person's to confirm (a code from someone else
          // makes it theirs): on their own terminal, or the fingerprint a script expects.
          const expect = o.expectFingerprint?.trim().toLowerCase();
          const r = await j.wait(expect !== undefined ? async (who) => who.fingerprint.toLowerCase() === expect : confirmLinkIdentity(identity.p2pCommand()));
          return { json: r, human: `This device is now ${r.address} (${r.did})${r.keyholder ? ", a key holder" : ""}.` };
        },
        // Linking waits up to 10 minutes for the other device, by design.
        { requireIdentity: false, noDeadline: true },
      ),
    );

  const devices = program
    .command("devices")
    .description("Your devices; `devices revoke <did>` removes one")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await ops.devices(app);
        return { json: { devices: r }, human: fmt.formatDevices(r) };
      }),
    );
  devices
    .command("revoke <did>")
    .description("Revoke a device: publish the next document version without it")
    .option("--json", "JSON output")
    .action(
      run(async (app, did: string) => {
        const r = await ops.revokeDevice(app, did);
        return { json: r, human: `Revoked ${r.revoked} (document version ${r.ver}). Re-issued ${fmt.plural(r.capsReissued, "cap")}${r.rejoined.length ? `, re-signed ${fmt.plural(r.rejoined.length, "circle membership")}` : ""}.` };
      }),
    );

  const profile = program.command("profile").description("Your public profile (bio, avatar, links)");
  profile
    .command("set")
    .description("Set profile fields (an empty value clears one)")
    .option("--bio <text>", "At most 280 characters")
    .option("--avatar <url|file>", "An https URL, or a PNG/JPEG/WebP/GIF file of at most 4 KiB as a data: URI")
    .option("--link <url>", "An https link (repeat for up to 5; replaces the list)", collect)
    .option("--clear", "Start from an empty profile")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { bio?: string; avatar?: string; link?: string[]; clear?: boolean }) => {
        const r = await ops.profileSet(app, { bio: o.bio, avatar: o.avatar, links: o.link, clear: o.clear });
        return { json: r, human: `Profile updated (document version ${r.ver}).` };
      }),
    );
  profile
    .command("show [user]")
    .description("Show a profile (yours by default)")
    .option("--json", "JSON output")
    .action(
      run(async (app, user: string | undefined) => {
        const r = await ops.profileShow(app, user);
        const p = r.profile;
        const lines = [r.address, ...(p.bio ? [`  ${p.bio}`] : []), ...p.links.map((l) => `  ${l}`)];
        if (p.avatar) lines.push(p.avatar.kind === "inline" ? "  avatar: inline image" : `  avatar: ${p.avatar.url} (not fetched)`);
        return { json: r, human: lines.join("\n") };
      }),
    );

  const proof = program.command("proof").description("Proofs that you also control a GitHub account or a domain (§2.6)");
  proof
    .command("add <kind> <claim>")
    .description("kind github <handle> [--gist <id>], or dns <domain>: prints what to publish")
    .option("--gist <id>", "The id of the public gist that will hold the proof")
    .option("--json", "JSON output")
    .action(
      run(async (app, kind: string, claim: string, o: { gist?: string }) => {
        const r = await ops.proofAdd(app, kind, claim, { gist: o.gist });
        return { json: r, human: r.pending ? r.publish : `Added ${kind}: ${r.claim} to your identity document (version ${r.ver}).\n${r.publish}` };
      }),
    );
  proof
    .command("verify <user>")
    .description("Check a user's proofs against GitHub and DNS")
    .option("--json", "JSON output")
    .action(
      run(async (app, user: string) => {
        await app.connect({ allowNone: true });
        const r = await ops.proofVerify(app, user);
        const lines = [r.address, ...(r.proofs.length ? r.proofs.map((p) => (p.verified ? `  ${p.display}` : `  ✗ ${p.kind}: ${p.claim} (${p.error})`)) : ["  no proofs"])];
        return { json: r, human: lines.join("\n") };
      }),
    );

  // ── friends ───────────────────────────────────────────────────────────────
  program
    .command("invite [label]")
    .description("Make a one-time invite code (and its https link): they open the link or run `p2p join <code>`, and are your friend (and in the code's circles) at once")
    .option("--circle <cid>", "A circle the code joins; repeat for up to 5 (default: your default circle, when you own or administer it)", collect)
    .option("--no-circle", "A friend invite only")
    .option("--to <user>", "Only this user may redeem it")
    .option("--ttl-days <n>", "Days the code lives (1-7, default 7)", posInt("--ttl-days"))
    .option("--relay <url>", "The relay holding the code (default: your first relay that takes it)")
    .option("--web", "Print only the code's web link (https://ix-infra.com/p2p/invite#…)")
    .option("--link", "Make the long friend-only invite link instead (`p2p accept <link>`)")
    .option("--uses <n>", "With --link: first-contact envelopes the link's cap admits per relay", posInt("--uses"))
    .option("--json", "JSON output")
    .action(
      run(async (app, label: string | undefined, o: { circle?: string[] | false; to?: string; ttlDays?: number; relay?: string; link?: boolean; uses?: number; web?: boolean }) => {
        if (o.link) {
          await app.connect({ allowNone: true });
          const r = await ops.invite(app, { to: o.to, uses: o.uses, ttlDays: o.ttlDays });
          return {
            json: r,
            human: `Send this link to ${r.invite.aud === "*" ? "the person you're inviting" : await app.addressOf(r.invite.aud)} over a channel you trust:\n\n${r.link}\n\nor, for a browser: ${r.web}\n\nThey run: p2p accept <link>${r.delivered ? `\n(also ${fmt.formatDelivery(r.delivered)})` : ""}`,
          };
        }
        if (o.uses !== undefined) throw new CliError("usage", "--uses goes with --link (a code works once)");
        if (o.link && o.web) throw new CliError("usage", "--web is the code's link; --link is the long friend-only one: pick one");
        let chosen: string[] | undefined;
        let noCircle = o.circle === false;
        let ttlDays = o.ttlDays;
        if (o.circle === undefined && canAsk(cmdOf(o))) {
          // No --circle: pick the circles (yours or ones you administer; open ones can't take a code).
          await app.connectAndDrain().catch(() => undefined);
          const list = (await ops.listCircles(app)).filter((c) => c.joined && (c.role === "owner" || c.role === "admin"));
          const choices: Choice[] = [
            { value: "", label: "Friend only (no circle)", exclusive: true },
            ...list.map((c) => ({
              value: c.cid,
              label: c.name,
              detail: `${fmt.plural(c.members, "member")} · ${c.policy}${c.isDefault ? " · default" : ""}`,
              ...(c.policy === "open" ? { disabled: "open: share its own link (p2p circle invite <cid> --link)" } : c.role === "owner" && !app.isKeyholder ? { disabled: "this device doesn't hold your identity key" } : {}),
              ...(c.isDefault ? { checked: true } : {}),
            })),
          ];
          if (!choices.some((c) => c.checked)) choices[0].checked = true;
          const picked = await ask({ message: `What should the invite${label ? ` for ${label}` : ""} join?`, choices, multi: true, max: 5 });
          chosen = picked.filter((v) => v !== "");
          noCircle = chosen.length === 0;
          if (ttlDays === undefined) {
            ttlDays = Number(
              (await ask({ message: "How long should it work?", choices: [{ value: "7", label: "7 days" }, { value: "3", label: "3 days" }, { value: "1", label: "1 day" }], initial: "7" }))[0],
            );
          }
        }
        const r = await ops.inviteCode(app, {
          label,
          ...(Array.isArray(o.circle) ? { circles: o.circle } : chosen?.length ? { circles: chosen } : {}),
          noCircle,
          to: o.to,
          ttlDays,
          relay: o.relay,
        });
        if (o.web) return { json: r, human: r.web };
        const days = Math.max(1, Math.round((r.expiresAt - Date.now() / 1000) / 86_400));
        const circles = r.circles.map((c) => `"${c.name}"`);
        return {
          json: r,
          pretty: (p) => pretty.prettyInvite(r, p),
          human: [
            `Your invite${r.label ? ` for ${r.label}` : ""} (works once, for ${fmt.plural(days, "day")}${r.to ? `, only for ${r.to.address}` : ""}):`,
            "",
            `  ${r.web}`,
            "",
            `or the code: ${r.code}  (${ops.joinCommandFor(r.web, r.privateRelay)})`,
            "",
            "Send them this message (it says how to install Peer2Peer if they don't have it):",
            "",
            ...r.message.split("\n").map((l) => `  ${l}`),
            "",
            `${circles.length ? `It makes them your friend and joins them to ${circles.join(", ")}. ` : "It makes them your friend. "}They see who it's from and what it joins, and say yes, before anything happens. Anyone who sees it before them can use it: you'll be told who joined, \`p2p remove <user>\` undoes it, and \`p2p invites revoke <code>\` cancels it before then.`,
          ].join("\n"),
        };
      }),
    );
  program
    .command("join <code>")
    .description("Redeem an invite code or its link (https://ix-infra.com/p2p/invite#…): shows who made it and the circles it joins, and on your yes makes you friends and joins them (creates your identity if there is none)")
    .option("--wait <seconds>", "How long to wait for the circles (default 15)", posInt("--wait"))
    .option("--preview", "Only show who made the code and what it joins; accept nothing (the code is then used up for anyone else)")
    .option("--confirmed", "You saw what the code offers (--preview) and want it: don't ask again")
    .option("-y, --yes", "For scripts: join without being asked, and join a circle even when no second member could confirm it (§3.3)")
    .option("--name <name>", "Your display name, if this creates your identity")
    .option("--allow-private-relay", "Accept a code whose relay is a loopback, link-local or private address (your own relay on your network; also P2P_ALLOW_PRIVATE_RELAY=1)")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, code: string, o: { wait?: number; yes?: boolean; name?: string; json?: boolean; preview?: boolean; confirmed?: boolean; allowPrivateRelay?: boolean }) => {
          if (o.preview) {
            const p = await ops.previewCode(app, code, { allowPrivateRelay: o.allowPrivateRelay });
            return { json: { preview: p }, human: `${ops.previewText(p)}\nTo join: p2p join --confirmed ${ops.shownCode(code)}` };
          }
          // An identity already here: what the relays deliver while the join waits (the inviter's adds of
          // us to the code's circles) is handled at once, so the join finishes now, not on the next command.
          if (app.keys || (await app.load(false))) receiving(app);
          const r = await ops.joinCode(app, code, {
            waitSec: o.wait,
            yes: o.yes,
            consent: o.confirmed,
            allowPrivateRelay: o.allowPrivateRelay,
            name: o.name,
            confirm: o.json || (!io.prompt && !io.select) ? undefined : (q) => confirmPrompt(q, false, ["Join", "Cancel"]),
            create: async (a, x) => {
              const c = await ops.init(a, x);
              receiving(a);
              io.err(`Created your identity ${c.address}. Only this device holds its key: save a backup with \`p2p backup show\`.`);
              return { userId: c.userId, address: c.address, relays: c.relays };
            },
          });
          return { json: r, human: joinLines(r).join("\n") };
        },
        { requireIdentity: false, waitDefault: 15 },
      ),
    );
  const invites = program
    .command("invites")
    .description("Your invite codes and what became of them; `invites revoke <code>` cancels one")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await ops.listCodes(app);
        return { json: { invites: r }, human: fmt.formatCodes(r), pretty: (p) => pretty.prettyCodes(r, p) };
      }),
    );
  invites
    .command("revoke [code]")
    .description("Cancel a code (the full code, or its first 4+ characters)")
    .option("--json", "JSON output")
    .action(
      pickable(["code"], run(async (app, picked: string | undefined) => {
        const code =
          picked ??
          (await pickOne(
            "Which invite should be cancelled?",
            (await ops.listCodes(app)).filter((c) => c.status === "open" || c.status === "taken").map((c) => ({ value: c.code, label: c.code, detail: [c.label, c.circles.map((x) => x.name).join(", ") || "friend only"].filter(Boolean).join(" · ") })),
            "no open invite to cancel",
          ));
        const r = await ops.revokeCode(app, code);
        return { json: r, human: r.revoked ? `Revoked ${r.code}${r.wasOpen ? "" : " (someone had already taken it: their join will be refused)"}.` : `${r.code} was already redeemed; use p2p remove.` };
      })),
    );
  program
    .command("remove [user]")
    .description("Undo a code redemption: unfriend them and take them out of the circles your codes added them to")
    .option("--json", "JSON output")
    .action(
      pickable(["user"], run(async (app, picked: string | undefined) => {
        const u = picked ?? (await pickOne("Who should be removed (unfriended, and out of the circles your codes added them to)?", await friendChoices(app), "no friends to remove"));
        const r = await ops.removeUser(app, u);
        const cs = r.circles.filter((c) => c.result === "removed" || c.result === "proposed");
        return { json: r, human: `Removed ${r.address}${r.unfriended ? " (unfriended)" : ""}${cs.length ? `; out of ${fmt.plural(cs.length, "circle")}` : ""}.` };
      })),
    );
  program
    .command("accept <link>")
    .description("Accept an invite link")
    .option("--allow-private-relay", "Accept a link whose relays are on loopback, link-local or private addresses (also P2P_ALLOW_PRIVATE_RELAY=1)")
    .option("--json", "JSON output")
    .action(
      run(async (app, l: string, o: { allowPrivateRelay?: boolean }) => {
        await ops.guardInviteLink(app, l, { allowPrivateRelay: o.allowPrivateRelay });
        const r = await ops.accept(app, l);
        return { json: r, human: `You and ${r.friend.address} are friends (accept ${fmt.formatDelivery(r.delivered)}).` };
      }),
    );
  program
    .command("friends")
    .description("Your friends, open invites and blocks")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${(e as Error).message}`));
        const r = await ops.friends(app);
        return { json: r, human: fmt.formatFriends(r), pretty: (p) => pretty.prettyFriends(r, p) };
      }),
    );
  program
    .command("unfriend [user]")
    .description("End a friendship (circle standing is unaffected, §3.2)")
    .option("--json", "JSON output")
    .action(
      pickable(["user"], run(async (app, picked: string | undefined) => {
        const u = picked ?? (await pickOne("Unfriend whom?", await friendChoices(app), "no friends yet"));
        const r = await ops.unfriend(app, u);
        return { json: r, human: `Unfriended ${r.address}; revoked ${fmt.plural(r.revoked, "cap")}.` };
      })),
    );
  program
    .command("block [user]")
    .description("Reject everything from a user, under every rule, and revoke their caps")
    .option("--json", "JSON output")
    .action(
      pickable(["user"], run(async (app, picked: string | undefined) => {
        const u = picked ?? (await pickOne("Block whom?", await friendChoices(app), "no friends to pick from: name the user"));
        const r = await ops.block(app, u);
        return { json: r, human: `Blocked ${r.address}; revoked ${fmt.plural(r.revoked, "cap")}.` };
      })),
    );
  program
    .command("unblock [user]")
    .description("Remove a block")
    .option("--json", "JSON output")
    .action(
      pickable(["user"], run(async (app, picked: string | undefined) => {
        const u =
          picked ??
          (await pickOne(
            "Unblock whom?",
            (await ops.friends(app)).blocked.map((b) => ({ value: b.userId, label: b.address })),
            "nobody is blocked",
          ));
        const r = await ops.unblock(app, u);
        return { json: r, human: `Unblocked ${r.address}.` };
      })),
    );
  program
    .command("petname <user> [name]")
    .description("Your own name for a user, shown instead of theirs (always with the fingerprint)")
    .option("--clear", "Remove the petname")
    .option("--json", "JSON output")
    .action(
      run(async (app, u: string, name: string | undefined, o: { clear?: boolean }) => {
        if (!name && !o.clear) throw new CliError("usage", "give a name, or --clear");
        const r = await ops.petname(app, u, o.clear ? undefined : name);
        return { json: r, human: r.petname ? `${r.userId} is now shown as ${r.address}.` : `Cleared the petname: ${r.address}.` };
      }),
    );

  // ── held ──────────────────────────────────────────────────────────────────
  const trust = program
    .command("trust")
    .description("Who may message a session that approves its own tool calls without the hold (the Claude mod reads this)");
  trust
    .command("ls")
    .description("Trusted users and circles, and everyone trusted right now")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const r = await trustOps.trustList(app);
        const lines = [
          ...r.users.map((u) => `${u.address} (${u.userId})${u.blocked ? " [blocked: not trusted]" : ""}`),
          ...r.circles.map((c) => `circle ${c.cid}${c.name ? ` "${c.name}"` : ""}: ${!c.joined ? "not joined: nobody" : c.open ? "open now (anyone who asks gets in): nobody" : `${c.members.length} members`}`),
        ];
        return { json: r, human: lines.length === 0 ? "Nobody is trusted." : lines.join("\n"), pretty: (p) => pretty.prettyTrust(r, p) };
      }),
    );
  for (const verb of ["add", "remove"] as const) {
    trust
      .command(`${verb} [target]`)
      .description(verb === "add" ? "Trust a user (full userId or name@fingerprint) or circle:<cid|name>" : "Stop trusting a user or circle:<cid|name>")
      .option("--json", "JSON output")
      .action(
        pickable(["target"], run(async (app, picked: string | undefined) => {
          let target = picked;
          if (target === undefined && verb === "add") {
            const friendsList = (await ops.friends(app)).friends;
            const cs = await circleChoices(app, (c) => c.joined);
            target = await pickOne(
              "Trust whom? (their messages reach a session that approves its own tool calls, without the hold)",
              // Names (or petnames) only: the fingerprint is what the person types below, from what they got
              // out of band, not something read off this list.
              [
                ...friendsList.map((f) => ({ value: f.userId, label: f.address.slice(0, Math.max(0, f.address.lastIndexOf("@"))) || f.address, detail: `friend since ${fmt.formatDate(f.since)}` })),
                ...cs.map((c) => ({ ...c, value: `circle:${c.value}`, label: `circle ${c.label}` })),
              ],
              "no friends or circles to trust yet",
            );
            if (!target.startsWith("circle:")) {
              // Kept from the typed form: trusting someone takes their fingerprint, typed, not a pick alone.
              const f = friendsList.find((x) => x.userId === target)!;
              const fp = f.address.slice(f.address.lastIndexOf("@") + 1);
              if (!io.prompt) throw new CliError("usage", "trust add needs their fingerprint typed: run `p2p trust add <name@fingerprint>`");
              const typed = (await io.prompt(`Type ${f.address.slice(0, f.address.lastIndexOf("@"))}'s fingerprint, as they gave it to you (xxxx-xxxx-xxxx-xxxx): `)).trim().toLowerCase().replace(/[\s-]/g, "");
              if (typed !== fp.toLowerCase().replace(/-/g, "")) throw new CliError("usage", "that fingerprint doesn't match: nobody was trusted");
            }
          } else if (target === undefined) {
            const r = await trustOps.trustList(app);
            target = await pickOne(
              "Stop trusting whom?",
              [...r.users.map((u) => ({ value: u.userId, label: u.address })), ...r.circles.map((c) => ({ value: `circle:${c.cid}`, label: `circle ${c.name ?? c.cid}` }))],
              "nobody is trusted",
            );
          }
          if (verb === "add") {
            const r = await trustOps.trustAdd(app, target);
            return { json: r, human: r.kind === "circle" ? `Trusted circle ${r.added}: its members, while they are in it.` : `Trusted ${r.address} (${r.added}).` };
          }
          const r = await trustOps.trustRemove(app, target);
          return { json: r, human: r.removed ? `No longer trusted: ${r.removed}.` : "That wasn't trusted." };
        })),
      );
  }
  trust
    .command("check <userId>")
    .description("Whether a user is trusted right now (judged from the verified circle state)")
    .option("--json", "JSON output")
    .action(
      run(async (app, userId: string) => {
        const r = await trustOps.trustCheck(app, userId);
        return { json: r, human: r.trusted ? `Trusted (${r.via}).` : "Not trusted." };
      }),
    );
  const held = program
    .command("held")
    .description("First contacts and circle invites waiting for you")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${(e as Error).message}`));
        const r = await ops.listHeld(app);
        return {
          json: { held: r },
          pretty: (p) => pretty.prettyHeld(r, p),
          human: r.length === 0 ? "Nothing held." : r.map((h) => `${h.id}  ${h.summary} from ${h.address}`).join("\n") + "\n\n`p2p held approve <id>` or `p2p held decline <id>`",
        };
      }),
    );
  held
    .command("approve [id]")
    .description("Act on a held item (accept the invite, join the circle, admit the joiner)")
    .option("--wait <seconds>", "Joining: how long to wait for confirmation answers", posInt("--wait"))
    .option("-y, --yes", "Joining: join even without a second confirmation")
    .option("--json", "JSON output")
    .action(
      pickable(["id"], run(async (app, picked: string | undefined, o: { wait?: number; yes?: boolean }) => {
        await (picked === undefined ? app.connectAndDrain().catch(() => undefined) : undefined);
        const id = picked ?? (await pickOne("Approve which?", await heldChoices(app), "nothing is held"));
        const h = await ops.getHeld(app, id);
        if (h.type === "rotation-dispute") {
          throw new CliError("usage", `choose who is really them: \`p2p identity dispute ${h.id} --keep <userId>\` or \`--neither\``);
        }
        if (h.type === "rotation-follow") {
          const r = await ops.followHeld(app, h);
          return { json: { type: h.type, ...r }, human: `This device moved with your identity: it is now ${r.address} (${r.did}).` };
        }
        if (h.type === "rotation") {
          const r = await ops.approveRotation(app, h);
          return { json: r, human: `You and ${String((r.friend as { address: string }).address)} (formerly ${await app.addressOf(String(r.from))}) are friends again under the new key; the old friendship ended.` };
        }
        if (h.type === "rotation-join") {
          const r = await ops.approveRotationJoin(app, h);
          return { json: r, human: `${await app.addressOf(String(r.member))} took ${await app.addressOf(String(r.old))}'s place in ${String(r.cid)} (circle version ${String(r.ver)}).` };
        }
        if (h.type === "invite") {
          const r = await ops.accept(app, h.invite!);
          return { json: { type: h.type, ...r }, human: `You and ${r.friend.address} are friends.` };
        }
        if (h.type === "circle-join") {
          const r = await ops.approveJoinRequest(app, h);
          await ops.dropHeld(app, (x) => x.id === h.id);
          return { json: { type: h.type, ...r }, human: `Admitted ${await app.addressOf(r.added)} (circle version ${r.ver}).` };
        }
        const r = await ops.joinFromHeld(app, h, { waitSec: o.wait ?? 20, yes: o.yes, confirm: (q) => confirmPrompt(q) });
        return { json: { type: h.type, ...r }, human: fmt.formatJoin(r) };
      }, { waitDefault: 20 })),
    );
  held
    .command("decline [id]")
    .description("Drop a held item")
    .option("--json", "JSON output")
    .action(
      pickable(["id"], run(async (app, picked: string | undefined) => {
        await (picked === undefined ? app.connectAndDrain().catch(() => undefined) : undefined);
        const id = picked ?? (await pickOne("Decline which?", await heldChoices(app), "nothing is held"));
        const h = await ops.getHeld(app, id);
        if (h.type === "rotation-dispute") {
          // Declining a contest keeps neither identity (both stay suspended).
          const r = await ops.resolveDispute(app, h.id, { neither: true });
          return { json: { declined: h.id, count: 1, ...r }, human: `Kept neither: both new keys stay suspended.` };
        }
        const gone = await ops.dropHeld(app, (x) => x.id === h.id);
        return { json: { declined: h.id, count: gone.length }, human: `Declined ${h.id}.` };
      })),
    );

  // ── circles ───────────────────────────────────────────────────────────────
  const circle = program.command("circle").description("Circles: groups whose members see each other's sessions (§3.3)");
  circle
    .command("create <name>")
    .description("Found a circle (you are its owner)")
    .option("--open", "Anyone with the link can join (policy open)")
    .option("--json", "JSON output")
    .action(
      run(async (app, name: string, o: { open?: boolean }) => {
        const r = await ops.createCircleCmd(app, name, { open: o.open });
        return { json: r, human: `Created "${r.name}" (${r.cid}), policy ${r.policy}.${r.link ? `\nAnyone with this link can join:\n\n${r.link}` : `\nInvite people: p2p circle invite ${r.cid} <user>  (or --link)`}` };
      }),
    );
  circle
    .command("invite [cid] [user]")
    .description("Invite a user (owner or admin), or print a link with --link")
    .option("--link", "Print a circle link instead")
    .option("--json", "JSON output")
    .action(
      pickable(["cid"], run(async (app, pickedCid: string | undefined, pickedUser: string | undefined, o: { link?: boolean }) => {
        const cid = pickedCid ?? (await pickOne("Invite to which circle?", await circleChoices(app, (c) => c.joined && (c.role === "owner" || c.role === "admin")), "you own or administer no circle: p2p circle create <name>"));
        let user = pickedUser;
        if (!user && !o.link && canAsk(cmdOf(o))) {
          const who = await pickOne("Invite whom?", [{ value: "", label: "Make a link instead (anyone with it can ask to join)" }, ...(await friendChoices(app))], "");
          if (who === "") o.link = true;
          else user = who;
        }
        if (o.link || !user) {
          if (!o.link) throw new CliError("usage", "name a user, or pass --link");
          const r = await ops.circleLink(app, cid);
          return { json: r, human: `${r.policy === "open" ? "Anyone with this link can join" : "This link lets people ask to join (you approve them)"}:\n\n${r.link}\n\nor, for a browser: ${r.web}` };
        }
        const r = await ops.inviteToCircle(app, cid, user);
        return { json: r, human: `Invited ${r.address} to ${r.cid}${r.added ? " (added to the members)" : ""}; ${fmt.formatDelivery(r.delivered)}.` };
      })),
    );
  circle
    .command("join <link>")
    .description("Join a circle from a link (confirms the circle with its owner first)")
    .option("--wait <seconds>", "How long to wait for answers (default 20)", posInt("--wait"))
    .option("-y, --yes", "Join even without a second confirmation")
    .option("--allow-private-relay", "Accept a link whose relays are on loopback, link-local or private addresses (also P2P_ALLOW_PRIVATE_RELAY=1)")
    .option("--json", "JSON output")
    .action(
      run(async (app, l: string, o: { wait?: number; yes?: boolean; allowPrivateRelay?: boolean }) => {
        const r = await ops.joinFromLink(app, l, { waitSec: o.wait ?? 20, yes: o.yes, confirm: (q) => confirmPrompt(q), allowPrivateRelay: o.allowPrivateRelay });
        if (r.status === "unconfirmed" || r.status === "waiting") process.exitCode = r.status === "waiting" ? 0 : 1;
        return { json: r, human: fmt.formatJoin(r) };
      }, { waitDefault: 20 }),
    );
  circle
    .command("leave [cid]")
    .description("Leave a circle (every member is told)")
    .option("--json", "JSON output")
    .action(
      pickable(["cid"], run(async (app, picked: string | undefined) => {
        const cid = picked ?? (await pickOne("Leave which circle? (every member is told)", await circleChoices(app, (c) => c.joined && c.role !== "owner"), "you're in no circle you could leave"));
        const r = await ops.leaveCircle(app, cid);
        return { json: r, human: `Left ${r.cid}; told ${fmt.plural(r.told, "member")}.` };
      })),
    );
  circle
    .command("ls")
    .description("Your circles")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${(e as Error).message}`));
        const r = await ops.listCircles(app);
        return { json: { circles: r }, human: fmt.formatCircles(r), pretty: (p) => pretty.prettyCircles(r, p) };
      }),
    );
  circle
    .command("members [cid]")
    .description("A circle's members and who stands in it")
    .option("--json", "JSON output")
    .action(
      pickable(["cid"], run(async (app, picked: string | undefined) => {
        await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${(e as Error).message}`));
        const cid = picked ?? (await pickOne("Which circle?", await circleChoices(app, (c) => c.joined), "you're in no circle"));
        const r = await ops.circleMembers(app, cid);
        return { json: r, human: fmt.formatMembers(r) };
      })),
    );
  circle
    .command("propose <cid> <op> <arg>")
    .description("add|remove|promote|demote <user>, or rename <name> (the owner applies it at once)")
    .option("--json", "JSON output")
    .action(
      run(async (app, cid: string, op: string, arg: string) => {
        const r = await ops.propose(app, cid, op, arg);
        return { json: r, human: r.applied ? `Applied: ${op} (circle version ${r.ver}).` : r.sentTo ? `Proposed ${op} to the owner, ${await app.addressOf(r.sentTo)}.` : "Nothing to change." };
      }),
    );
  circle
    .command("transfer <cid> [user]")
    .description("Hand the circle to a member (they consent first with --accept)")
    .option("--accept", "As the new owner: consent to take over")
    .option("--consent <jws>", "A consent you received another way")
    .option("--json", "JSON output")
    .action(
      run(async (app, cid: string, user: string | undefined, o: { accept?: boolean; consent?: string }) => {
        const r = await ops.transfer(app, cid, user, o);
        return { json: r, human: o.accept ? `Sent your consent to the owner. They finish with: p2p circle transfer ${cid} <you>` : `Handed ${cid} to ${String(r.address)} (version ${String(r.ver)}).` };
      }),
    );
  circle
    .command("hold <cid> [state]")
    .description("on|off: hold admins' proposals and rotated members for your approval (`p2p held`), as the owner")
    .option("--json", "JSON output")
    .action(
      run(async (app, cid: string, state: string | undefined) => {
        if (state !== undefined && state !== "on" && state !== "off") throw new CliError("usage", "state is on or off");
        const r = await ops.setCircleHold(app, cid, state === undefined ? undefined : state === "on");
        return { json: r, human: `${r.cid}: changes ${r.hold ? "wait for your approval" : "apply by themselves"}.` };
      }),
    );
  circle
    .command("policy <cid> <policy>")
    .description("invite (you approve joins) or open (anyone with the link joins)")
    .option("--json", "JSON output")
    .action(
      run(async (app, cid: string, policy: string) => {
        const r = await ops.setPolicy(app, cid, policy);
        return { json: r, human: `${r.cid} is now ${r.policy} (version ${r.ver}).` };
      }),
    );
  circle
    .command("default [cid]")
    .description("Your default circle: what invites join, and what `p2p project share` with no circle shares a project with (sessions follow their project, never this); --none for none")
    .option("--none", "No default circle")
    .option("--json", "JSON output")
    .action(
      run(async (app, picked: string | undefined, o: { none?: boolean }) => {
        let cid = picked;
        if (!cid && !o.none && canAsk(cmdOf(o))) {
          const v = await pickOne(
            "Which circle is your default (for invites, and for `p2p project share` with no circle)?",
            [...(await circleChoices(app, (c) => c.joined)).map((c) => ({ ...c, ...(c.detail?.includes("open") ? { detail: `${c.detail} · anyone its owner admits sees them` } : {}) })), { value: "", label: "None" }],
            "",
          );
          if (v === "") o.none = true;
          else cid = v;
        }
        if (!cid && !o.none) throw new CliError("usage", "name a circle, or --none");
        const r = await ops.setDefaultCircle(app, o.none ? undefined : cid);
        return {
          json: r,
          human: r.defaultCircle
            ? `Default circle: ${r.defaultCircle} (invites join it; \`p2p project share\` with no circle shares a project with it). Sessions follow their project: \`p2p project share\` in a repository shares its sessions.`
            : "No default circle. Sessions follow their project: `p2p project share` in a repository shares its sessions.",
        };
      }),
    );

  // ── sessions ──────────────────────────────────────────────────────────────
  program
    .command("ls")
    .description("Live sessions of your friends, circle-mates and other devices")
    .option("--all", "Include sessions that aren't live")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { all?: boolean }) => {
        await app.connectAndDrain().catch((e) => io.err(`p2p: offline: ${(e as Error).message}`));
        const r = await ops.listPeers(app, { all: o.all });
        const relays = app.relayStatus ?? { listed: app.relays, connected: [], failed: app.relays.map((u) => ({ url: u, reason: "not connected" })) };
        return { json: { peers: r, relays }, human: fmt.formatPeers(r) + (relays.failed.length ? `\n\n! unreachable: ${relays.failed.map((f) => f.url).join(", ")}` : ""), pretty: (p) => pretty.prettyPeers(r, relays, p) };
      }),
    );
  program
    .command("send [text...]")
    .description("Send a message to a peer session (text from args or stdin)")
    .option("--from-session <sid>", "Your session id (on a terminal: default tui, as `p2p tui` sends)")
    .option("--to <address>", "name@fingerprint, userId or petname, optionally \"[ref]\" or /sid; another session of yours on this device only by \"[ref]\" or /sid, never the sending session itself (on a terminal: picked from a list)")
    .option("--notify-when-idle", "Tell this session when the target next goes idle")
    .option("--stdin", "Read the text from stdin (also: a single `-` as the text)")
    .option("--project-dir <dir>", "Another folder the session works in (repeatable): binds it to that project too, which only ever narrows who it may reach", collect)
    .option("--project-dirs-over [why]", "The front end dropped folders past its cap or couldn't resolve a path: the session is private (why: unresolved, folders or front, comma-separated; use the = form)")
    .option("--json", "JSON output")
    .action(async (text: string[], o: { fromSession?: string; to?: string; notifyWhenIdle?: boolean; stdin?: boolean; projectDir?: string[]; projectDirsOver?: boolean | string }, cmd: Command) => {
      // Without a picker these stay required, with commander's own error (as before they were requiredOption).
      if (!canAsk(cmd)) {
        if (o.fromSession === undefined) cmd.error("error: required option '--from-session <sid>' not specified", { code: "commander.missingMandatoryOptionValue" });
        if (o.to === undefined) cmd.error("error: required option '--to <address>' not specified", { code: "commander.missingMandatoryOptionValue" });
      }
      return (sendAction as (...a: unknown[]) => Promise<void>)(text, o, cmd);
    });
  const sendAction = run(async (app, text: string[], o: { fromSession?: string; to?: string; notifyWhenIdle?: boolean; stdin?: boolean; projectDir?: string[]; projectDirsOver?: boolean | string }) => {
        if (o.to === undefined) {
          await app.connectAndDrain().catch(() => undefined);
          const peers = await ops.listPeers(app, { all: true });
          const targets: Choice[] = [];
          for (const p of peers.filter((x) => !x.self)) targets.push({ value: `${p.own} [${p.ref}]`, label: `${p.address} [${p.ref}] ${p.label}`, detail: [p.live ? p.state : "offline", p.summary].filter(Boolean).join(" · ") });
          for (const f of (await ops.friends(app)).friends) targets.push({ value: f.userId, label: `${f.address} (any session)` });
          o.to = await pickOne("Send to whom?", targets, "nobody to send to yet: p2p invite");
        }
        // On a terminal with no --from-session: sent as `p2p tui` sends, and said so.
        const fromTui = o.fromSession === undefined;
        if (fromTui) o.fromSession = TUI_SESSION;
        // The person's own session (projects.ts): only from a terminal. Named by a script or an agent, it is refused.
        // And never from inside an agent's session (its environment, or a Claude Code or Codex ancestor),
        // even under a pseudo-terminal: only the person's own terminal, or their front end's token.
        const personOk = projects.personHere(app);
        if (fromTui && !personOk) throw new CliError("refused", "`p2p send` with no --from-session sends as you, from your own terminal; inside an agent's session, send from that session (--from-session)");
        const person = o.fromSession === TUI_SESSION && canAsk(cmdOf(o)) && personOk;
        // Without the front end's token, the person confirms on their own terminal: a send as them, or the
        // first send from a session nobody has used yet (a process detached from every terminal can't).
        // (A first send from a new session is confirmed where every new session is: projects.ts bindSession.)
        if (!app.front && (person || fromTui)) {
          if (!(await confirmTty(`p2p send from session ${o.fromSession} to ${o.to}.`))) {
            throw new CliError("refused", "this send needs your \"yes\" on your own terminal (read from the terminal itself, never stdin or a flag)");
          }
        }
        if (text.length === 0 && !o.stdin && !o.notifyWhenIdle && io.prompt) {
          text = [(await io.prompt("Message: ")).trim()];
          if (text[0] === "") throw new CliError("cancelled", "no message: nothing was sent");
        }
        // Text: the arguments; or stdin with --stdin / `-`; or, with neither and no --notify-when-idle,
        // stdin when it isn't a terminal. A pure subscription never waits on a pipe that may not close.
        const fromStdin = o.stdin || (text.length === 1 && text[0] === "-");
        let body = fromStdin ? "" : text.join(" ");
        if ((fromStdin || (body === "" && !o.notifyWhenIdle)) && io.readStdin) body = (await io.readStdin({ implicit: !fromStdin })).replace(/\n$/, "");
        if (fromStdin && body === "" && !o.notifyWhenIdle) throw new CliError("usage", "stdin was empty");
        if (!fromStdin && body === "" && !o.notifyWhenIdle) {
          // review L2: without --stdin, stdin is only waited on briefly.
          throw new CliError("usage", "no message text: give it as arguments, or pipe it in with --stdin (or `-` as the text), which waits for the whole input");
        }
        // Sending from the tui session (a person at a terminal, no --from-session): the recipient is added to
        // that session's roster first, so the message can land there and their replies reach `p2p tui`.
        // Never with --from-session, and never off a terminal (fromTui is only reachable through a picker).
        // Shared only with the send (undone if it fails): sessions.sendSharing.
        let shared = "";
        let r: Awaited<ReturnType<typeof ops.sendMessage>>;
        if (fromTui) {
          const s = await ops.sendSharing(app, { fromSession: o.fromSession!, to: o.to!, text: body, notifyWhenIdle: o.notifyWhenIdle });
          r = s.result;
          if (s.shared) shared = `shared session tui with ${s.shared.address}\n`;
        } else r = await ops.sendMessage(app, { fromSession: o.fromSession!, to: o.to!, text: body, notifyWhenIdle: o.notifyWhenIdle, ...(o.projectDir ? { projectDirs: o.projectDir } : {}), ...(o.projectDirsOver !== undefined && o.projectDirsOver !== false ? { projectDirsOver: o.projectDirsOver === true || o.projectDirsOver === "" ? true : [o.projectDirsOver] } : {}), ...(person ? { person: true } : {}) });
        const tail = r.notifyWhenIdle ? `; will notify when ${r.to.address} [${r.to.ref}] is idle` : "";
        const where = r.to.own === r.to.userId ? `${r.to.address} [${r.to.ref}]` : `${r.to.address} (in your session ${r.to.sid})`;
        const ago = (ms: number) => {
          const m = Math.max(0, Math.round((Date.now() - ms) / 60_000));
          return m < 1 ? "just now" : m < 120 ? `${m} min ago` : `${Math.round(m / 60)} h ago`;
        };
        const until = (ms: number) => `expires in ${Math.max(1, Math.round((ms - Date.now()) / 86_400_000))} days`;
        // The person's own sends cross no project boundary, but say which one this folder has (projects.ts).
        const here = person ? await ops.showProject(app, projects.sessionWorkdir(app.env)).catch(() => undefined) : undefined;
        const boundary = here ? `\nproject ${here.name} here is ${here.policy === "private" ? "private (agent sessions in it reach only your own devices)" : "shared"}; this send was yours, from your terminal` : "";
        const taint = fromTui ? await ops.tuiTaintNote(app, r.to.userId).catch(() => undefined) : undefined;
        const from = fromTui ? `\nsent from session tui; replies show in \`p2p tui\`${boundary}${taint ? `\nnote: ${taint}` : ""}` : "";
        if (r.queued && r.state === "outbox") {
          return { json: r, human: `${shared}Queued for ${where}: this device can't reach a relay right now; it goes out when one is back (${until(r.expiresAt!)})${tail}.${from}` };
        }
        if (r.queued) {
          return { json: r, human: `${shared}Sent to ${where}, which is offline (last seen ${ago(r.lastSeen!)}): delivered via ${fmt.plural(r.relays, "relay")}, held there until it reconnects (${until(r.expiresAt!)})${tail}.${from}` };
        }
        return { json: r, human: `${shared}${r.delivered ? `Sent to ${where}: delivered via ${fmt.plural(r.relays, "relay")}${tail}.` : `Subscribed${tail}.`}${from}` };
      }, { sends: true });
  program
    .command("receipt <event>")
    .description("Send a delivery receipt for a message this session has (§4.3; the front end that shows messages reports the outcome)")
    .requiredOption("--from-session <sid>", "The session that has the message")
    .requiredOption("--outcome <outcome>", "shown | held | declined | expired | ended")
    .option("--json", "JSON output")
    .action(
      run(async (app, event: string, o: { fromSession: string; outcome: string }) => {
        const sid = sessions.checkSid(o.fromSession, "--from-session");
        // Only the session's front end (or, outside an agent, a caller for an unregistered session) reports for it.
        await projects.assertSpeaksFor(app, sid);
        const r = await sendReceipt(app, { eventId: event, fromSession: sid, outcome: o.outcome });
        return { json: r, human: r.sent ? `Receipt sent: ${r.outcome}.` : `No receipt sent (${r.reason}).` };
      }),
    );
  program
    .command("own-agents [state] [did]")
    .description(
      "Whether messages from your own agent sessions skip the hold in a session that approves its own tool calls: `hold` (the default), `deliver` (you only; `--devices <did…|all-other>` for only your other devices' sessions), or `check <did>` (a front end, at delivery)",
    )
    .option("--devices <devices...>", "With deliver: only messages from these other devices of yours (their device ids, or all-other); this device's agent sessions stay held")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, state: string | undefined, did: string | undefined, o: { devices?: string[] }) => {
          if (state !== undefined && state !== "hold" && state !== "deliver" && state !== "check") throw new CliError("usage", "p2p own-agents [hold|deliver [--devices <did…|all-other>]|check <did>]");
          if (state === "check") {
            if (!did || !isDid(did)) throw new CliError("usage", "p2p own-agents check <did>: a v3 device id");
            return { json: { did, deliver: ownAgentsDeliverFrom(app.home, did, app.did) }, human: ownAgentsDeliverFrom(app.home, did, app.did) ? "deliver" : "hold" };
          }
          if (did !== undefined) throw new CliError("usage", "p2p own-agents [hold|deliver [--devices <did…|all-other>]]");
          const devices = o.devices?.flatMap((d) => d.split(",")).map((d) => d.trim()).filter(Boolean);
          if (devices !== undefined && state !== "deliver") throw new CliError("usage", "--devices goes with deliver");
          if (devices !== undefined && !(devices.length === 1 && devices[0] === "all-other") && !devices.every((d) => isDid(d) && d !== app.did)) {
            throw new CliError("usage", "--devices takes your other devices' ids (p2p devices) or all-other, never this device");
          }
          // Turning the hold off widens what drives a session: the person only, never an agent. Turning it back on never asks.
          if (state === "deliver") await projects.assertPersonForWidening(app, devices ? "own-agents deliver --devices" : "own-agents deliver", app.confirmTty);
          if (state === "hold") {
            await updateFileConfigField(app, "ownAgentsDeliver", () => ({ next: false, result: undefined }));
            await updateFileConfigField(app, "ownDevicesDeliver", () => ({ next: [], result: undefined }));
          } else if (state === "deliver" && devices) {
            await updateFileConfigField(app, "ownDevicesDeliver", () => ({ next: devices.length === 1 && devices[0] === "all-other" ? "all-other" : devices, result: undefined }));
          } else if (state === "deliver") {
            await updateFileConfigField(app, "ownAgentsDeliver", () => ({ next: true, result: undefined }));
          }
          const on = ownAgentsDeliver(app.home);
          const list = ownDevicesDeliver(app.home);
          const some = list === "all-other" ? "all your other devices" : list.length > 0 ? `your devices ${list.join(", ")}` : undefined;
          return {
            json: { ownAgents: on ? "deliver" : "hold", devices: list },
            human: on
              ? "Messages from your own agent sessions reach a session that approves its own tool calls without the hold."
              : `Messages from your own agent sessions wait for Deliver in a session that approves its own tool calls (your own terminal's here are delivered)${some ? `, except those from ${some}` : ""}.`,
          };
        },
        // `check` and `--devices` need this device's id.
        {},
      ),
    );
  program
    .command("receipts [state]")
    .description("Whether this user sends delivery receipts: `on` or `off` sets it (config.json; P2P_RECEIPTS overrides)")
    .option("--json", "JSON output")
    .action(
      run(
        async (app, state: string | undefined) => {
          if (state !== undefined && state !== "on" && state !== "off") throw new CliError("usage", "p2p receipts [on|off]");
          if (state !== undefined) await updateFileConfigField(app, "receipts", () => ({ next: state === "on", result: undefined }));
          const r = receiptsSetting(app);
          const note = r.overridden ? " (P2P_RECEIPTS is set and overrides config.json)" : "";
          return { json: r, human: `Delivery receipts are ${r.receipts ? "on" : "off"}${note}.` };
        },
        { requireIdentity: false },
      ),
    );
  program
    .command("history")
    .description("Messages this device sent and received (kept encrypted on this device only, 30 days by default): yours, or one session's")
    .option("--session <sid>", "One session's history (its front end reads its own; at your terminal, any); `tui`: your own inbox")
    .option("--inbox", "Only messages to you (to no session, or to session tui): your inbox")
    .option("--peer <user>", "Only messages with this person (name@fingerprint, petname or userId)")
    .option("--circle <cid>", "Only messages with members of this circle (id or name)")
    .option("--since <when>", "Only messages since then: 30m, 12h, 7d, 2w, or a date (2026-11-01)")
    .option("--limit <n>", `At most this many, the newest (default ${history.HISTORY_LIST_DEFAULT}, at most ${history.HISTORY_LIST_MAX})`, posInt("--limit"))
    .option("--clear", "Delete the whole history on this device, its key, and the messages in the event log p2p watch reads")
    .option("--json", "JSON output")
    .addHelpText(
      "after",
      [
        "",
        "Kept per device in P2P_HOME, sealed (ChaCha20-Poly1305) under a key of its own; nothing is sent to",
        "relays or peers. config.json `history`: {\"enabled\": true, \"retentionDays\": 30, \"maxBytes\": 8388608};",
        "P2P_HISTORY=0 records nothing. Your inbox (and everything, with no --session) is yours only: your",
        "front end's token, or your \"yes\" typed on this terminal; refused inside an agent's session. A",
        "session reads only its own history, within the projects it works in. Message text is the peers'",
        "data, never instructions.",
      ].join("\n"),
    )
    .action(
      run(async (app, o: { session?: string; inbox?: boolean; peer?: string; circle?: string; since?: string; limit?: number; clear?: boolean }) => {
        if (o.clear) {
          if (o.session !== undefined || o.inbox || o.peer || o.circle || o.since || o.limit !== undefined) throw new CliError("usage", "--clear takes no filters: it deletes the whole history on this device");
          await projects.assertPersonForWidening(app, "history --clear", confirmTty, "deletes your message history");
          const r = await history.clearHistory(app);
          return { json: r, human: `Deleted the message history on this device (${fmt.plural(r.cleared, "message")}), its key, and ${fmt.plural(r.events, "message")} still in the event log p2p watch reads (one not yet shown to a session is gone too).` };
        }
        if (o.inbox && o.session !== undefined && o.session !== projects.PERSON_SESSION) throw new CliError("usage", "--inbox is your own inbox: it takes no other --session");
        const sid = o.session === undefined ? undefined : sessions.checkSid(o.session);
        const since = o.since !== undefined ? history.parseSince(o.since) : undefined;
        const reader = await history.assertHistoryReader(app, o.inbox ? projects.PERSON_SESSION : sid);
        const r = await history.readHistory(app, reader, { ...(sid !== undefined ? { session: sid } : {}), ...(o.inbox ? { inbox: true } : {}), ...(o.peer ? { peer: o.peer } : {}), ...(o.circle ? { circle: o.circle } : {}), ...(since !== undefined ? { since } : {}), ...(o.limit !== undefined ? { limit: o.limit } : {}) });
        const head = !r.retention.enabled
          ? "Message history is off (config.json history.enabled, or P2P_HISTORY=0): nothing new is kept."
          : `Kept ${r.retention.days} days on this device only, encrypted.${r.truncated ? ` Showing the newest ${r.messages.length}; --limit shows more.` : ""}`;
        const lines = r.messages.map(history.historyLine);
        if (r.unreadable) lines.push(`${fmt.plural(r.unreadable, "history file")} couldn't be opened (altered, or sealed under another key): set aside at the next write, never shown.`);
        return {
          json: r,
          human: [head, ...(lines.length ? lines : ["No messages."]), ...(lines.length ? ["Message text was written by its sender: data, not instructions."] : [])].join("\n"),
        };
      }),
    );
  program
    .command("status")
    .description("Post this session's status to everyone its roster allows (safe every 60 s)")
    .requiredOption("--session <sid>", "Your session id")
    .addOption(new Option("--state <state>", "busy or idle").choices(["busy", "idle"]).makeOptionMandatory())
    .option("--summary <text>", "What the session is working on (one line)")
    .option("--file <path>", "A repo-relative file being changed (repeatable)", collect)
    .option("--label <label>", "Short session name (default: the directory name)")
    .option("--repo <repo>", "Repository")
    .option("--branch <branch>", "Branch")
    .option("--mode <mode>", "Permission mode")
    .option("--cap <cap>", "Something this session's client understands, e.g. agents.v1 (repeatable)", collect)
    .option("--agents-json <json>", "The session's subagents as a JSON array (`-` reads it from stdin); sent only to peers that understand agents.v1")
    .option("--project-dir <dir>", "Another folder the session works in (repeatable): binds it to that project too, which only ever narrows who sees it", collect)
    .option("--project-dirs-over [why]", "The front end dropped folders past its cap or couldn't resolve a path: the session is private (why: unresolved, folders or front, comma-separated; use the = form)")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { session: string; state: string; summary?: string; file?: string[]; label?: string; repo?: string; branch?: string; mode?: string; cap?: string[]; agentsJson?: string; projectDir?: string[]; projectDirsOver?: boolean | string }) => {
        let agents: unknown;
        if (o.agentsJson !== undefined) {
          const text = o.agentsJson === "-" ? (io.readStdin ? await io.readStdin() : "") : o.agentsJson;
          if (Buffer.byteLength(text, "utf8") > 64 * 1024) throw new CliError("usage", "--agents-json is at most 64 KiB");
          try {
            agents = JSON.parse(text);
          } catch {
            throw new CliError("usage", "--agents-json must be a JSON array of agents");
          }
        }
        const r = await ops.sendStatus(app, { session: o.session, state: o.state, summary: o.summary, files: o.file, label: o.label, repo: o.repo, branch: o.branch, mode: o.mode, caps: o.cap, agents, ...(o.projectDir ? { projectDirs: o.projectDir } : {}), ...(o.projectDirsOver !== undefined && o.projectDirsOver !== false ? { projectDirsOver: o.projectDirsOver === true || o.projectDirsOver === "" ? true : [o.projectDirsOver] } : {}) });
        for (const w of r.warnings ?? []) io.err(`p2p: ${w}`);
        const n = r.delivered.length;
        return {
          json: r,
          human: `${r.status.state} posted to ${fmt.plural(n, "peer")}${r.failed.length ? `; ${r.failed.length} unreachable (${r.failed.map((f) => f.address).join(", ")})` : ""}.\n${fmt.formatRoster(r.roster)}`,
          pretty: (p) => pretty.prettyStatus(r, p),
        };
      }),
    );
  const session = program.command("session").description("Session settings");
  session
    .command("roster <sid>")
    .description("Who may see and message this session: within what its project allows (`p2p project`), private until shared")
    .option("--circle <cid>", "Share with a circle you joined")
    .option("--private", "Only the listed people")
    .option("--add <user>", "Add a participant (repeatable)", collect)
    .option("--remove <user>", "Remove a participant (repeatable)", collect)
    .option("--json", "JSON output")
    .action(
      run(async (app, sid: string, o: { circle?: string; private?: boolean; add?: string[]; remove?: string[] }) => {
        const r = await ops.roster(app, sid, o);
        return { json: { roster: r }, human: fmt.formatRoster(r) };
      }),
    );

  // ── projects (projects.ts): who sees sessions working in a repository ──────
  const project = program
    .command("project")
    .description("Who sees sessions working in this project (a git repository, or a folder): private until you share it")
    .addHelpText(
      "after",
      [
        "",
        "A project is private until you share it: only your own devices see its sessions, their files,",
        "footprints and summaries, and none of its sessions can send to anyone else. A session that works",
        "in several projects reaches only who all of them share. Policies live only on this device;",
        `nothing in a repository can widen them (a committed ${projects.PRIVATE_MARKER} can only make it private).`,
      ].join("\n"),
    );
  const projectView = (v: projects.ProjectView) => {
    const lines = [`${v.name}  ${v.policy === "private" ? "private" : "shared"}${v.kind === "git" ? (v.remote ? `  (${v.remote})` : "  (git, no remote)") : v.covers ? "  (folder, and its subfolders)" : "  (folder)"}`, `  ${v.root}`];
    if (v.policy === "private") lines.push(`  only your own devices see its sessions${v.why === "unmapped" ? " (never shared: `p2p project share <circle>` in it)" : v.why ? ` (${v.why})` : ""}`);
    for (const c of v.circles) lines.push(`  circle ${c.name ?? c.cid} (${c.cid})${c.open ? ", open: anyone its owner admits" : ""}${c.joined ? "" : ", not joined: ignored"}`);
    for (const p of v.people) lines.push(`  ${p.address}`);
    if (v.graph) lines.push(`  graph: ${projects.graphTargetLine(v.graph)}`, `    (${projects.graphPlaintextNote(v.graph)})`);
    return lines.join("\n");
  };
  project
    .command("share [circles...]")
    .description("Share the project here with circles you joined (and friends with --person); on a terminal with none named, pick them")
    .option("--person <user>", "A friend to share it with too (repeatable)", collect)
    .option("--add", "Keep what it is shared with already (default: replace it)")
    .option("--subfolders", "A folder outside git: the share covers its subfolders too (never past a repository, a .p2p-private or a folder with its own policy; refused for a home, temporary or system folder). Without it, the share is for that folder alone")
    .option("--dir <path>", "The project's folder (default: P2P_WORKDIR, else the current directory)")
    .option("--json", "JSON output")
    .action(
      run(async (app, named: string[], o: { person?: string[]; add?: boolean; subfolders?: boolean; dir?: string }) => {
        const dir = o.dir ?? projects.sessionWorkdir(app.env);
        let circlesIn = [...named];
        let people = [...(o.person ?? [])];
        if (circlesIn.length + people.length === 0 && canAsk(cmdOf(o))) {
          const here = await ops.showProject(app, dir);
          const cs = await circleChoices(app, (c) => c.joined);
          const fs = (await friendChoices(app)).map((f) => ({ ...f, value: `person:${f.value}` }));
          const picked = await ask({
            intro: [`Project ${here.name} (${here.root}) is ${here.policy}.`, "Everyone you pick sees its sessions: status, summary, files and footprints, and its agents may message them."],
            message: `Share ${here.name} with:`,
            choices: [...cs.map((c) => ({ ...c, checked: c.value === app.self?.defaultCircle || here.circles.some((x) => x.cid === c.value) })), ...fs],
            multi: true,
            max: projects.MAX_PROJECT_SHARES,
          });
          circlesIn = picked.filter((v) => !v.startsWith("person:"));
          people = picked.filter((v) => v.startsWith("person:")).map((v) => v.slice("person:".length));
          if (circlesIn.length + people.length === 0) throw new CliError("cancelled", "nothing picked: nothing was shared");
        } else if (circlesIn.length + people.length === 0) {
          // The quick way for someone who relied on the default circle: share this project with it.
          const def = app.self?.defaultCircle;
          if (!def) throw new CliError("usage", "name a circle (or --person <friend>) to share this project with");
          circlesIn = [def];
        }
        const r = await ops.shareProject(app, dir, { circles: circlesIn, people, ...(o.add ? { add: true } : {}), ...(o.subfolders ? { subfolders: true } : {}) });
        for (const w of r.warnings) io.err(`p2p: warning: ${w}`);
        return { json: { project: r.project, ...(r.warnings.length ? { warnings: r.warnings } : {}) }, human: `Shared. Sessions in ${r.project.name} are seen by:\n${projectView(r.project)}` };
      }),
    );
  project
    .command("private")
    .description("Make the project here private: only your own devices see its sessions (the default)")
    .option("--dir <path>", "The project's folder (default: P2P_WORKDIR, else the current directory)")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { dir?: string }) => {
        const v = await ops.makeProjectPrivate(app, o.dir ?? projects.sessionWorkdir(app.env));
        return { json: { project: v }, human: `${v.name} is private: sessions in it reach only your own devices, from their next status on (a session that worked in it stays private until it ends).` };
      }),
    );
  project
    .command("ls")
    .description("Projects with a policy on this device, and who sees each")
    .option("--json", "JSON output")
    .action(
      run(async (app) => {
        const all = await ops.listProjects(app);
        return { json: { projects: all }, human: all.length === 0 ? "No project is shared: every session is seen only by your own devices. `p2p project share <circle>` in a repository shares it." : all.map(projectView).join("\n\n") };
      }),
    );
  project
    .command("show")
    .description("The project here (its id, root, remote) and who sees its sessions")
    .option("--dir <path>", "The project's folder (default: P2P_WORKDIR, else the current directory)")
    .option("--json", "JSON output")
    .action(
      run(async (app, o: { dir?: string }) => {
        const v = await ops.showProject(app, o.dir ?? projects.sessionWorkdir(app.env));
        return { json: { project: v }, human: projectView(v) };
      }),
    );

  session
    .command("show <sid>")
    .description("A session's bound projects, who each is shared with, and every reason it is private (read only; yours: refused inside an agent's session)")
    .option("--json", "JSON output")
    .action(
      run(async (app, sid: string) => {
        const v = await ops.showSession(app, sessions.checkSid(sid, "sid"));
        const lines = [`session ${v.sid}: ${v.policy === "none" ? "not bound to any project" : v.policy}`];
        if (v.reasons.length) lines.push("  private because:", ...v.reasons.map((r) => `    - ${r.why}`));
        if (v.remedy) lines.push(`  ${v.remedy.charAt(0).toUpperCase()}${v.remedy.slice(1)}`);
        if (v.policy === "shared") lines.push(`  reaches: ${[...(v.circles ?? []).map((c) => `circle ${c}`), ...(v.people ?? [])].join(", ") || "nobody"}`);
        if (v.constraints) lines.push(`  ${fmt.plural(v.constraints, "bound")} from messages your other sessions sent it`);
        for (const p of v.projects) {
          lines.push("", ...projectView(p).split("\n"));
          if (p.underOver) lines.push("  covering many of its subfolders");
          else if (p.under?.length) lines.push(`  covering ${p.under.join(", ")}`);
        }
        return { json: { session: v }, human: lines.join("\n") };
      }),
    );

  session
    .command("bound <sid>")
    .description("Bind a session to the bound an own-session message it took carried (front ends call it on Deliver; narrowing only)")
    .requiredOption("--bound <json>", '"private" or {"circles": [...], "people": [...]}, as the message carried it')
    .option("--json", "JSON output")
    .action(
      run(async (app, sid: string, o: { bound: string }) => {
        let v: unknown;
        try {
          v = JSON.parse(o.bound);
        } catch {
          throw new CliError("usage", "--bound must be JSON");
        }
        const r = await ops.bindBound(app, sid, v);
        return { json: { project: r }, human: `session ${sid}: ${r.policy}${r.why ? ` (${r.why})` : ""}` };
      }),
    );

  program
    .command("doctor [user]")
    .description("Explain why sessions are or aren't visible: this device's identity, relays, clock, circle and sharing, or (with a user) whether you can see them")
    .option("--json", "JSON output")
    .addHelpText(
      "after",
      [
        "",
        "Each check is ✓ (fine), ✗ (a problem, with a fix) or ? (unknown, with what would tell). Read-only: it",
        "publishes and sends nothing. Every network step is bounded (P2P_DOCTOR_TIMEOUT_MS, default 5000).",
        "<user> is a name@fingerprint, petname, name or userId.",
      ].join("\n"),
    )
    .action(
      run(
        async (app, user: string | undefined) => {
          const r = await ops.doctor(app, { version: VERSION, ...(user !== undefined ? { user } : {}) });
          const plain = doctorOps.formatDoctor(r);
          return { json: r, human: plain, pretty: (p) => pretty.prettyDoctor(r, plain, p) };
        },
        { requireIdentity: false, readOnly: true },
      ),
    );

  program
    .command("watch")
    .description("Stream accepted events as JSON lines (reconnects silently; Ctrl-C to stop)")
    .requiredOption("--session <sid>", "Your session id")
    .option("--jsonl", "One compact JSON line per event (the default)")
    .option("--json", "Alias for --jsonl")
    .action(async (o: { session: string }) => {
      const app = makeApp(deps.env, io);
      try {
        await app.load(true);
        sessions.checkSid(o.session);
      } catch (e) {
        const j = toErrorJson(e);
        io.err(`p2p watch: ${String(j.error)}: ${String(j.reason)}`);
        process.exitCode = 1;
        return;
      }
      const ctl = new AbortController();
      const onSignal = () => ctl.abort();
      process.on("SIGINT", onSignal);
      process.on("SIGTERM", onSignal);
      deps.signal?.addEventListener("abort", onSignal);
      try {
        const code = await ops.watch(app, {
          session: o.session,
          signal: ctl.signal,
          log: (m) => io.err(m),
          write: deps.writeLine ?? stdoutWriter(ctl),
        });
        process.exitCode = code;
      } catch (e) {
        const j = toErrorJson(e);
        io.err(`p2p watch: ${String(j.error)}: ${String(j.reason)}`);
        process.exitCode = 1;
      } finally {
        process.off("SIGINT", onSignal);
        process.off("SIGTERM", onSignal);
      }
    });

  program
    .command("tui")
    .description("Full-screen terminal UI: people and their sessions, held items, messages, send, health (your own terminal only)")
    .option("--session <sid>", "This TUI's session id (default: tui)")
    .action(async (o: { session?: string }) => {
      process.exitCode = await tuiCommand(
        { env: deps.env, io, version: VERSION, makeApp: (env, i) => makeApp(env, i), front: deps.front === true, ...(deps.isTTY !== undefined ? { isTTY: deps.isTTY } : {}), ...(deps.terminal ? { terminal: deps.terminal } : {}), ...(deps.signal ? { signal: deps.signal } : {}) },
        o,
      );
    });

  // `p2p` with no arguments on a terminal (main maps it here): who you are, relay health, friends
  // online, held items, the commands to try. Piped, `p2p` alone still prints the help.
  program
    .command("home", { hidden: true })
    .description("The home screen")
    .action(
      run(
        async (app) => {
          if (!(await app.load(false))) return { json: {}, human: "", pretty: (p) => pretty.prettyHome({ relays: [], online: [], friends: 0, held: 0 }, p) };
          await app.connectAndDrain().catch(() => undefined);
          const st = app.relayStatus;
          const relays = app.relays.map((u) => ({ url: u, ok: st ? st.connected.includes(u) : false }));
          const peers = await ops.listPeers(app, {}).catch(() => []);
          const f = await ops.friends(app).catch(() => ({ friends: [] }));
          const held = await ops.listHeld(app).catch(() => []);
          const online = [...new Set(peers.filter((p) => p.live && !p.self).map((p) => p.address))];
          const d = { address: app.self ? await app.addressOf(app.userId) : undefined, relays, online, friends: f.friends.length, held: held.length };
          return { json: d, human: "", pretty: (p) => pretty.prettyHome(d, p) };
        },
        { requireIdentity: false },
      ),
    );

  registerExtensionCommands(program, extensions, { io, run, confirm: confirmPrompt, collect });
  codexCommands(program, deps, io);

  return program;
}

/** The running `p2p` script (the bundled p2p.mjs, or dist/bin.js), for Codex to start. */
function selfScript(deps: ProgramDeps): string {
  const p = deps.scriptPath ?? process.argv[1] ?? "";
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/**
 * `p2p codex …`: the Codex bridge (@peer2peer/codex-bridge). The MCP server
 * and hooks run from this same script, so the single-file p2p.mjs carries
 * everything Codex needs.
 */
function codexCommands(program: Command, deps: ProgramDeps, io: Io): void {
  const out = (json: boolean, o: codex.Output) => {
    if (json) io.out(safeJson(o.json));
    else if (o.human) io.out(safeTerminal(o.human));
  };
  const fail = (json: boolean, e: unknown) => {
    const err = e instanceof codex.CodexCommandError ? { error: e.code, reason: e.message } : toErrorJson(e);
    if (json) io.out(safeJson(err));
    else io.err(`p2p codex: ${String(err.error)}: ${String(err.reason)}`);
    process.exitCode = 1;
  };
  const self = () => [process.execPath, selfScript(deps)];

  const c = program.command("codex").description("Peer2Peer for OpenAI Codex: MCP server, hooks, installer, held messages");
  c.command("install")
    .description("Print the Codex config (MCP server, hooks, AGENTS.md lines); --write applies it (backs up first, idempotent)")
    .option("--write", "Edit config.toml, hooks.json and AGENTS.md in the Codex home")
    .option("--remove", "Remove the peer2peer entries instead (with --write)")
    .option("--codex-home <dir>", "The Codex home (default: CODEX_HOME, else ~/.codex)")
    .option("--json", "JSON output")
    .action(async (o: { write?: boolean; remove?: boolean; codexHome?: string; json?: boolean }) => {
      try {
        const script = selfScript(deps);
        out(Boolean(o.json), codex.installCommand({ env: deps.env, node: deps.nodeCommand ?? process.execPath, script, ...(o.codexHome ? { codexHome: resolve(o.codexHome) } : {}), write: o.write, remove: o.remove }));
      } catch (e) {
        fail(Boolean(o.json), e);
      }
    });
  c.command("mcp")
    .description("The stdio MCP server Codex starts for each session (not for interactive use)")
    .action(async () => {
      const stdin = deps.stdin ?? process.stdin;
      const stop = () => stdin.destroy();
      process.once("SIGTERM", stop);
      process.once("SIGINT", stop);
      try {
        // P2P_BIN applies only from the user-level Codex config (the server checks).
        await codex.runMcpServer({ bin: self(), env: deps.env, stdin, stdout: deps.stdout ?? process.stdout, stderr: process.stderr });
      } finally {
        process.off("SIGTERM", stop);
        process.off("SIGINT", stop);
      }
    });
  c.command("hook <event>")
    .description("A Codex hook: reads the event's JSON on stdin (configured by `p2p codex install`)")
    .option("--managed-by <installer>", "Marks the hook entries `p2p codex install` wrote (ignored when run)")
    .action(async (event: string) => {
      try {
        const stdin = io.readStdin ? await io.readStdin() : "";
        const binNames = [deps.env.P2P_BIN?.trim(), selfScript(deps)].filter((v): v is string => !!v);
        const answer = await codex.runHook(event, stdin, { home: codex.bridgeHome(deps.env), binNames, ...((deps.env.HOME ?? deps.env.USERPROFILE) ? { homeDir: deps.env.HOME ?? deps.env.USERPROFILE } : {}) });
        if (answer) io.out(answer);
      } catch {
        // A hook never breaks Codex: no output, exit 0.
      }
      process.exitCode = 0;
    });
  c.command("sessions")
    .description("This machine's live Codex sessions on Peer2Peer (sid, who sees them, held messages)")
    .option("--json", "JSON output")
    .action(async (o: { json?: boolean }) => {
      try {
        out(Boolean(o.json), await codex.sessionsCommand({ env: deps.env }));
      } catch (e) {
        fail(Boolean(o.json), e);
      }
    });
  c.command("held")
    .description("Messages your Codex sessions hold for you, with previews (run in your own terminal)")
    .option("--json", "JSON output")
    .action(async (o: { json?: boolean }) => {
      try {
        out(Boolean(o.json), await codex.heldCommand({ env: deps.env }));
      } catch (e) {
        fail(Boolean(o.json), e);
      }
    });
  for (const verb of ["release", "decline"] as const) {
    c.command(`${verb} <id>`)
      .description(verb === "release" ? "Hand a held message to its Codex session's model" : "Drop a held message (its sender gets one notice)")
      .option("--json", "JSON output")
      .action(async (id: string, o: { json?: boolean }) => {
        try {
          const isTTY = deps.isTTY ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);
          out(Boolean(o.json), await codex.resolveCommand({ env: deps.env, id, decline: verb === "decline", io: { isTTY, ...(io.prompt ? { prompt: io.prompt } : {}) } }));
        } catch (e) {
          fail(Boolean(o.json), e);
        }
      });
  }
}

/** Writes a line to stdout; resolves false once the reader is gone (EPIPE). */
export function stdoutWriter(ctl: AbortController): (line: string) => Promise<boolean> {
  let gone = false;
  process.stdout.on("error", () => {
    gone = true;
    ctl.abort();
  });
  return (line) =>
    new Promise((resolve) => {
      if (gone || ctl.signal.aborted) return resolve(false);
      try {
        process.stdout.write(line + "\n", (err) => resolve(!err && !gone));
      } catch {
        resolve(false);
      }
    });
}

/** The extensions the user enabled (P2P_EXTENSIONS, else config.json `extensions`); see extensions.ts. */
async function loadInstalled(deps: ProgramDeps): Promise<ExtensionRegistry> {
  const home = resolveHome(deps.env);
  let config: FileConfig = {};
  try {
    config = readFileConfig(home);
  } catch {
    // a broken config.json is reported by the command itself
  }
  const say = (m: string) => deps.io.err(safeTerminal(m));
  return loadExtensions({ env: deps.env, home, config, warn: say, log: say });
}

/** Parses and runs; returns the exit code. */
export async function main(argvIn: string[], deps: ProgramDeps): Promise<number> {
  // The person token: checked once, then taken out of the environment before anything runs, so no
  // child process (git, ix, an extension's tool) can read it (projects.ts).
  {
    // A copy without it (an embedder's object is left as it was); the process's own environment loses it too.
    const env = { ...deps.env };
    const front = deps.front === true || projects.takePersonToken(env, resolveHome(env));
    if (deps.env === process.env) delete process.env.P2P_PERSON_TOKEN;
    deps = { ...deps, front, env };
  }
  // `--no-input` anywhere before `--`: no pickers, no questions (as a script would run).
  const end = argvIn.indexOf("--");
  const head = end < 0 ? argvIn : argvIn.slice(0, end);
  let argv = argvIn;
  if (head.includes("--no-input")) {
    argv = [...head.filter((a) => a !== "--no-input"), ...(end < 0 ? [] : argvIn.slice(end))];
    deps = { ...deps, noInput: true };
  }
  // `p2p` alone on a terminal: the home screen. Piped, it prints the help as before.
  if (argv.length === 0 && deps.io.pretty && !deps.noInput) argv = ["home"];
  // `doctor` is read-only and needs no extension: loading one records where it came from
  // (<home>/extension-locations.json) and runs its code, so it is skipped.
  const isDoctor = argv.find((a) => !a.startsWith("-")) === "doctor";
  const extensions = deps.extensions ?? (isDoctor ? new ExtensionRegistry() : await loadInstalled(deps));
  const program = buildProgram({ ...deps, extensions });
  process.exitCode = 0;
  try {
    await program.parseAsync(argv, { from: "user" });
  } catch (e) {
    if (e instanceof CommanderError) {
      if (e.code === "commander.helpDisplayed" || e.code === "commander.version" || e.code === "commander.help") return 0;
      return 1;
    }
    const j = toErrorJson(e);
    deps.io.err(safeTerminal(`p2p: ${String(j.error)}: ${String(j.reason)}`));
    return 1;
  }
  return typeof process.exitCode === "number" ? process.exitCode : 0;
}
