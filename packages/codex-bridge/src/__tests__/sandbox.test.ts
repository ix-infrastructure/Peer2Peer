// Copyright 2026 Ix Infrastructure Inc.
//
// Codex's sandbox and P2P_HOME (sandbox.ts): the status `p2p doctor` reports, and the minimal
// config.toml edit `p2p sandbox enable` makes. Every other line, comment and their order stay; it
// is idempotent; what it can't edit safely it leaves to the person.
//
// With P2P_CODEX_SANDBOX=1 and `codex` on PATH, the edited config is also run through
// `codex sandbox` (no login needed) in a throwaway CODEX_HOME: a read and a write under the denied
// folder fail, the workspace stays readable.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { codexDenyPaths, codexSandboxStatus, planCodexSandbox, SANDBOX_BEGIN, SANDBOX_END } from "../sandbox.js";

const HOME = "/home/ann";
const DENY = ["~/.p2p"];
const plan = (text: string | null) => planCodexSandbox(text, DENY, HOME);
const edited = (text: string | null): string => {
  const p = plan(text);
  if (p.kind !== "edit") throw new Error(`expected an edit, got ${JSON.stringify(p)}`);
  return p.after;
};

describe("codexDenyPaths", () => {
  it("writes P2P_HOME as ~/… under the home folder, else absolute, and adds its real path when it differs", () => {
    expect(codexDenyPaths("/home/ann/.p2p", HOME)).toEqual(["~/.p2p"]);
    expect(codexDenyPaths("/srv/p2p", HOME)).toEqual(["/srv/p2p"]);
    expect(codexDenyPaths("/home/ann/.p2p", HOME, "/data/ann/p2p")).toEqual(["~/.p2p", "/data/ann/p2p"]);
  });
});

describe("codexSandboxStatus", () => {
  it("is off without a profile, under sandbox_mode, and under a built-in profile", () => {
    expect(codexSandboxStatus(null, DENY, HOME).state).toBe("off");
    expect(codexSandboxStatus('model = "x"\n', DENY, HOME).detail).toMatch(/no permissions profile/);
    expect(codexSandboxStatus('sandbox_mode = "workspace-write"\n', DENY, HOME).detail).toMatch(/can't deny reads/);
    expect(codexSandboxStatus('default_permissions = ":workspace"\n', DENY, HOME).detail).toMatch(/built-in profile :workspace/);
    expect(codexSandboxStatus('default_permissions = ":danger-full-access"\n', DENY, HOME).detail).toMatch(/without a sandbox/);
  });

  it("is on when the active profile (or one it extends) denies P2P_HOME or a folder above it", () => {
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p.filesystem]\n"~/.p2p" = "deny"\n', DENY, HOME).state).toBe("on");
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p]\nextends = "base"\n[permissions.base]\nextends = ":workspace"\n[permissions.base.filesystem]\n"/home/ann" = "deny"\n', DENY, HOME).state).toBe("on");
    // Inline tables and dotted keys count too.
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p]\nfilesystem = { "~/.p2p" = "deny" }\n', DENY, HOME).state).toBe("on");
  });

  it("is off when an entry inside P2P_HOME opens it again, or a broader grant wins", () => {
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p.filesystem]\n"~/.p2p" = "deny"\n"~/.p2p/cli" = "read"\n', DENY, HOME).detail).toMatch(/opens part of ~\/\.p2p again/);
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p.filesystem]\n"~/.p2p" = "write"\n', DENY, HOME).state).toBe("off");
    expect(codexSandboxStatus('default_permissions = "p"\n[permissions.p.filesystem]\n"~/elsewhere" = "deny"\n', DENY, HOME).state).toBe("off");
  });

  it("names config profiles whose sandbox_mode turns it off", () => {
    const s = codexSandboxStatus('default_permissions = "p"\n[permissions.p.filesystem]\n"~/.p2p" = "deny"\n[profiles.fast]\nsandbox_mode = "danger-full-access"\n', DENY, HOME);
    expect(s.state).toBe("on");
    expect(s.notes.join()).toMatch(/codex --profile fast/);
  });

  it("is unknown for text it can't read with confidence", () => {
    expect(codexSandboxStatus('default_permissions = "p\n', DENY, HOME).state).toBe("unknown");
  });
});

/** What Codex enforced before an edit, and after it: writes (0 none, 1 workspace, 2 everything; +0.5 for extra roots) and network. */
function effective(text: string): { writes: number; network: boolean } {
  const lines = text.split("\n").map((l) => l.trim());
  const top = (k: string) => {
    for (const l of lines) {
      if (l.startsWith("[")) return undefined;
      const m = new RegExp(`^${k} = "([^"]*)"`).exec(l);
      if (m) return m[1];
    }
    return undefined;
  };
  const mode = top("sandbox_mode");
  const dp = top("default_permissions");
  const rank = (b: string | undefined) => (b === "workspace-write" || b === ":workspace" ? 1 : b === "danger-full-access" || b === ":danger-full-access" ? 2 : 0);
  const sww = text.includes("[sandbox_workspace_write]") ? text.slice(text.indexOf("[sandbox_workspace_write]")) : "";
  if (mode) return { writes: rank(mode) + (mode === "workspace-write" && sww.includes("writable_roots") ? 0.5 : 0), network: mode === "workspace-write" && sww.includes("network_access = true") };
  if (dp && !dp.startsWith(":")) {
    const block = text.slice(text.indexOf(`[permissions.${dp}]`));
    const ext = block.split("\n").find((l) => l.startsWith("extends = "))?.slice(11, -1);
    return { writes: rank(ext) + (block.includes('" = "write"') ? 0.5 : 0), network: block.includes(".network]\nenabled = true") };
  }
  return { writes: rank(dp), network: false };
}

describe("never broader than before", () => {
  const fixtures = [
    null,
    'model = "x"\n',
    'sandbox_mode = "read-only"\n',
    'default_permissions = ":workspace"\nsandbox_mode = "read-only"\n',
    'default_permissions = ":read-only"\n',
    'default_permissions = ":workspace"\n',
    'sandbox_mode = "workspace-write"\n',
    'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = ["/w"]\n',
    'sandbox_mode = "read-only"\n[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = ["/w"]\n',
    '[sandbox_workspace_write]\nnetwork_access = true\n',
  ];
  for (const f of fixtures) {
    it(`${JSON.stringify(f)}: writes and network don't widen`, () => {
      const p = plan(f);
      expect(p.kind).toBe("edit");
      if (p.kind !== "edit") return;
      const before = effective(f ?? "");
      const after = effective(p.after);
      expect(after.writes, p.after).toBeLessThanOrEqual(before.writes);
      if (!before.network) expect(after.network, p.after).toBe(false);
    });
  }

  it("sandbox_mode decides over default_permissions, as in Codex", () => {
    const p = plan('default_permissions = ":workspace"\nsandbox_mode = "read-only"\n');
    expect(p).toMatchObject({ kind: "edit", base: ":read-only" });
    if (p.kind === "edit") expect(p.after).toContain('extends = ":read-only"');
  });

  it("carries [sandbox_workspace_write] over only under sandbox_mode = workspace-write", () => {
    for (const t of ['[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = ["/w"]\n', 'sandbox_mode = "read-only"\n[sandbox_workspace_write]\nnetwork_access = true\n']) {
      const after = edited(t);
      expect(after).not.toContain("[permissions.peer2peer.network]");
      expect(after).not.toContain('"/w" = "write"');
    }
  });

  it("refuses when sandbox_mode is set beside an existing peer2peer profile", () => {
    expect(plan('sandbox_mode = "read-only"\n[permissions.peer2peer]\nextends = ":workspace"\n').kind).toBe("manual");
  });
});

describe("planCodexSandbox", () => {
  it("adds a profile extending :read-only to an empty or missing config (Codex's per-folder default can't be expressed)", () => {
    for (const text of [null, ""]) {
      const after = edited(text);
      expect(after).toBe(
        [
          'default_permissions = "peer2peer" # p2p sandbox',
          "",
          SANDBOX_BEGIN,
          "[permissions.peer2peer]",
          `description = "Codex's sandbox, with Peer2Peer's keys (P2P_HOME) denied to its commands"`,
          'extends = ":read-only"',
          "",
          "[permissions.peer2peer.filesystem]",
          '"~/.p2p" = "deny"',
          SANDBOX_END,
          "",
        ].join("\n"),
      );
      const p = plan(text);
      expect(p.kind === "edit" && p.assumed).toBe(true);
      // The person may choose :workspace instead.
      expect(planCodexSandbox(text, DENY, HOME, { baseWhenUnset: ":workspace" })).toMatchObject({ kind: "edit", base: ":workspace", assumed: true });
      expect(codexSandboxStatus(after, DENY, HOME).state).toBe("on");
      expect(plan(after).kind).toBe("already");
    }
  });

  it("keeps every other line, comment and the peer2peer MCP block exactly as they were", () => {
    const before = [
      "# my Codex config",
      'model = "gpt-x" # inline comment',
      'approval_policy = "on-request"',
      "",
      "# >>> peer2peer (managed by `p2p codex install`; edit with care) >>>",
      "[mcp_servers.peer2peer]",
      'command = "/usr/bin/node"',
      'args = ["/x/p2p.mjs", "codex", "mcp"]',
      "# <<< peer2peer <<<",
      "",
      "[tui]",
      'notes = """',
      "[not.a.table]",
      '"""',
      "",
    ].join("\n");
    const after = edited(before);
    const lines = after.split("\n");
    // The new top-level key goes after the last top-level one; everything before the block is as it was.
    expect(lines.slice(0, 4)).toEqual(["# my Codex config", 'model = "gpt-x" # inline comment', 'approval_policy = "on-request"', 'default_permissions = "peer2peer" # p2p sandbox']);
    expect(after.replace('default_permissions = "peer2peer" # p2p sandbox\n', "").startsWith(before.trimEnd())).toBe(true);
    expect(plan(after).kind).toBe("already");
  });

  it("replaces sandbox_mode (profiles don't combine with it), carrying writable_roots and network_access over", () => {
    const before = ['sandbox_mode = "workspace-write"', "", "[sandbox_workspace_write]", 'writable_roots = ["/home/ann/.cache/x", "~/build"]', "network_access = true", ""].join("\n");
    const p = plan(before);
    if (p.kind !== "edit") throw new Error(JSON.stringify(p));
    expect(p.after).toMatch(/^# sandbox_mode = "workspace-write" # p2p sandbox: replaced by default_permissions = "peer2peer"/);
    expect(p.after).toMatch(/\ndefault_permissions = "peer2peer" # p2p sandbox\n/);
    expect(p.after).toMatch(/\[permissions\.peer2peer\.filesystem\]\n"~\/\.p2p" = "deny"\n"\/home\/ann\/\.cache\/x" = "write"\n"~\/build" = "write"\n/);
    expect(p.after).toMatch(/\[permissions\.peer2peer\.network\]\nenabled = true\n/);
    // The old table stays, as it was (Codex ignores it without sandbox_mode).
    expect(p.after).toContain('[sandbox_workspace_write]\nwritable_roots = ["/home/ann/.cache/x", "~/build"]\nnetwork_access = true\n');
    expect(p.edits.some((e) => "before" in e && e.before === 'sandbox_mode = "workspace-write"')).toBe(true);
    expect(codexSandboxStatus(p.after, DENY, HOME).state).toBe("on");
    expect(plan(p.after).kind).toBe("already");
  });

  it("extends :read-only for sandbox_mode = read-only, and switches a built-in default_permissions to the new profile", () => {
    expect(edited('sandbox_mode = "read-only"\n')).toMatch(/extends = ":read-only"/);
    const after = edited('default_permissions = ":read-only"\n');
    expect(after).toMatch(/^default_permissions = "peer2peer" # p2p sandbox \(was ":read-only"\)\n/);
    expect(after).toMatch(/extends = ":read-only"/);
  });

  it("adds the deny to the person's own active profile, in its filesystem table or a new one", () => {
    const withTable = 'default_permissions = "mine"\n\n[permissions.mine]\nextends = ":workspace"\n\n[permissions.mine.filesystem]\n"~/.ssh" = "deny"\n';
    expect(edited(withTable)).toBe('default_permissions = "mine"\n\n[permissions.mine]\nextends = ":workspace"\n\n[permissions.mine.filesystem]\n"~/.p2p" = "deny"\n"~/.ssh" = "deny"\n');
    const without = 'default_permissions = "mine"\n\n[permissions.mine]\nextends = ":workspace"\n';
    const after = edited(without);
    expect(after).toBe('default_permissions = "mine"\n\n[permissions.mine]\nextends = ":workspace"\n\n[permissions.mine.filesystem] # p2p sandbox\n"~/.p2p" = "deny"\n');
    expect(plan(after).kind).toBe("already");
  });

  it("adds only the missing path when P2P_HOME moved", () => {
    const after = edited(null);
    const p = planCodexSandbox(after, ["~/.p2p", "/srv/p2p"], HOME);
    if (p.kind !== "edit") throw new Error(JSON.stringify(p));
    expect(p.edits).toEqual([{ add: '"/srv/p2p" = "deny"' }]);
    expect(p.after.match(/\[permissions\.peer2peer\]/g)?.length).toBe(1);
  });

  it("keeps CRLF line endings", () => {
    const after = edited('model = "x"\r\n\r\n[tui]\r\nfoo = 1\r\n');
    expect(after.includes("\n") && !/[^\r]\n/.test(after)).toBe(true);
    expect(codexSandboxStatus(after, DENY, HOME).state).toBe("on");
  });

  it("leaves what it can't edit safely to the person, with the lines to add", () => {
    const cases: [string, RegExp][] = [
      ['sandbox_mode = "danger-full-access"\n', /without a sandbox/],
      ['default_permissions = ":danger-full-access"\n', /without a sandbox/],
      ['default_permissions = "mine"\n[permissions.mine]\nfilesystem = { "~/.ssh" = "deny" }\n', /inline table or dotted keys/],
      ['sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = [\n  "/a",\n]\n', /one-line list/],
      ['sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nexclude_slash_tmp = true\n', /exclude_slash_tmp/],
      ['model = "unterminated\n', /couldn't be read/],
    ];
    for (const [text, why] of cases) {
      const p = plan(text);
      expect(p.kind, text).toBe("manual");
      if (p.kind !== "manual") continue;
      expect(p.reason).toMatch(why);
      expect(p.snippet).toMatch(/\[permissions\.peer2peer\.filesystem\]\n"~\/\.p2p" = "deny"/);
    }
  });
});

const codexBin = (() => {
  try {
    return execFileSync("/usr/bin/which", ["codex"], { encoding: "utf8" }).trim();
  } catch {
    return "";
  }
})();

describe.skipIf(process.env.P2P_CODEX_SANDBOX !== "1" || !codexBin)("the edit, enforced by `codex sandbox` (P2P_CODEX_SANDBOX=1)", () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "p2p-codex-sbx-")));
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("denies a read and a write under P2P_HOME; the workspace stays readable", () => {
    const home = join(root, "home");
    const p2pHome = join(home, "pp-home");
    const codexHome = join(root, "codex-home");
    const ws = join(root, "ws");
    for (const d of [p2pHome, codexHome, ws]) mkdirSync(d, { recursive: true });
    writeFileSync(join(p2pHome, "secret"), "s");
    writeFileSync(join(ws, "file"), "w");
    writeFileSync(join(codexHome, "config.toml"), edited('sandbox_mode = "workspace-write"\n').replace('"~/.p2p"', JSON.stringify(p2pHome)));
    const env = { PATH: process.env.PATH ?? "", HOME: home, CODEX_HOME: codexHome };
    const run = (...cmd: string[]) => spawnSync(codexBin, ["sandbox", "--", ...cmd], { cwd: ws, env, encoding: "utf8", timeout: 30_000 });
    expect(run("/bin/cat", join(p2pHome, "secret")).status).not.toBe(0);
    expect(run("/bin/sh", "-c", `echo x > ${JSON.stringify(join(p2pHome, "w"))}`).status).not.toBe(0);
    const ok = run("/bin/cat", join(ws, "file"));
    expect(ok.status).toBe(0);
    expect(ok.stdout).toBe("w");
  });
});
