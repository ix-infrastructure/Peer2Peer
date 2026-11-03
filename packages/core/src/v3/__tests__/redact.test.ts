// Copyright 2026 Ix Infrastructure Inc.
//
// redactSecrets and stripAbsolutePaths (footprint P1 review M3, and the
// residual cases of the pre-release review), table-driven.

import { describe, expect, it } from "vitest";
import { redactSecrets, stripAbsolutePaths } from "../sanitize.js";

const STRIP: [string, string][] = [
  ["Fix /Users/sam/x.ts and src/y.ts", "Fix and src/y.ts"],
  ["Read ~/notes and ~\\win", "Read and"],
  ["Open ~sam/private/plan.md now", "Open now"],
  ["Windows C:\\Users\\sam and C:/x and \\\\srv\\share", "Windows and and"],
  ["Check $HOME/.aws, %USERPROFILE%\\.ssh.", "Check,"],
  ["see [/etc/hosts] and {/var/log/x}", "see [] and {}"],
  ["path:/Users/sam/a and a,/opt/b", "path: and a,"],
  ["tag </home/sam/x> and (/srv/y) and \"/tmp/z\" and '/root/k'", "tag <> and () and \"\" and ''"],
  ["open file:///Users/sam/secret.txt please", "open please"],
  ["/peers add ben then /review", "/peers add ben then /review"],
  ["fetch https://example.com/docs/page", "fetch https://example.com/docs/page"],
  ["Refactor packages/codex-bridge/src/knobs.ts", "Refactor packages/codex-bridge/src/knobs.ts"],
  // pre-release review low: `; | * @ ! -` and smart quotes may come right before a path too.
  ["run;/etc/passwd now", "run; now"],
  ["a|/usr/bin/x", "a|"],
  ["glob */home/sam/x", "glob *"],
  ["mail user@/var/data", "mail user@"],
  ["wow!/tmp/x", "wow!"],
  ["flag -/opt/thing", "flag -"],
  ["quote \u201C/Users/sam/x\u201D and \u2018/root/y\u2019", "quote \u201C and \u2018"],
  ["re-run a-b/c and x--y", "re-run a-b/c and x--y"],
  ["keep src/a-b/c.ts", "keep src/a-b/c.ts"],
];

const REDACT: [string, string][] = [
  ["key sk-proj-abcDEF1234567890xyz", "key [redacted]"],
  ["ghp_abcdefghijklmnopqrstuvwxyz0123", "[redacted]"],
  ["gho_abcdefghijklmnopqrstuvwxyz0123", "[redacted]"],
  ["github_pat_11ABCDEFG0123456789_abcdefghij", "[redacted]"],
  ["gitlab glpat-abcdefghij0123456789", "gitlab [redacted]"],
  ["stripe rk_live_abcdefghij0123 rk_test_abcdefghij0123", "stripe [redacted] [redacted]"],
  ["stripe pk_live_abcdefghij0123 sk_live_abcdefghij0123", "stripe [redacted] [redacted]"],
  ["slack xoxb-1234567890-abcdefghij xoxe-1-abcdefghij12", "slack [redacted] [redacted]"],
  ["slack app xapp-1-A0123456789-abcdef", "slack app [redacted]"],
  ["aws AKIAIOSFODNN7EXAMPLE", "aws [redacted]"],
  ["aws secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws secret [redacted]"],
  ["gcp AIzaSyA1234567890abcdefghijklmnopqrstu", "gcp [redacted]"],
  ["oauth GOCSPX-abcdefghij123456", "oauth [redacted]"],
  ["pem -----BEGIN OPENSSH PRIVATE KEY----- b3Bl", "pem [redacted]"],
  ["jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl", "jwt [redacted]"],
  ["hex 0123456789abcdef0123456789abcdef", "hex [redacted]"],
  ["b64 aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldDEy", "b64 [redacted]"],
  ["b64+ abcd+efgh/ijkl1234=mnopqrstuvwxyz0123", "b64+ [redacted]"],
  ["db postgres://admin:hunter2@db.internal:5432/app", "db postgres://[redacted]@db.internal:5432/app"],
  ["git https://x-token:ghs_abc@github.com/o/r", "git https://[redacted]@github.com/o/r"],
  // Not secrets: kept.
  ["commit 0123456789abcdef0123456789abcdef01234567", "commit 0123456789abcdef0123456789abcdef01234567"],
  ["sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
  ["id 123e4567-e89b-12d3-a456-426614174000", "id 123e4567-e89b-12d3-a456-426614174000"],
  ["Refactor packages/codex-bridge/src/knobs.ts", "Refactor packages/codex-bridge/src/knobs.ts"],
  ["mods/claude/peer2peer/hooks/register.tsx", "mods/claude/peer2peer/hooks/register.tsx"],
  ["internationalization-of-the-settings-page", "internationalization-of-the-settings-page"],
  ["commit abc1234 and skill-search for sk-learn", "commit abc1234 and skill-search for sk-learn"],
  // pre-release review low: keyword secrets and bearer tokens (the keyword stays, the value goes).
  ["password=hunter2 ok", "password=[redacted] ok"],
  ["PASSWD: s3cr3t", "PASSWD: [redacted]"],
  ["client_secret=abc123", "client_secret=[redacted]"],
  ["auth token: abcdef", "auth token: [redacted]"],
  ["api_key=XYZ", "api_key=[redacted]"],
  ["API-KEY: x1", "API-KEY: [redacted]"],
  ["apikey=1", "apikey=[redacted]"],
  ["Authorization: Bearer abcdefgh123", "Authorization: Bearer [redacted]"],
  ["token: Bearer abcdefgh1234", "token: [redacted] [redacted]"],
  ["Bearer short", "Bearer short"],
  // pre-release review L4: any case of Bearer; JSON- and quote-wrapped keyword secrets (a quoted value goes whole).
  ["bearer abcdefgh123 and BEARER abcdefgh456", "bearer [redacted] and BEARER [redacted]"],
  ['{"password": "hunter2", "user": "sam"}', '{"password": "[redacted]", "user": "sam"}'],
  ["{'api_key': 'abc def'}", "{'api_key': '[redacted]'}"],
  ['password="two words" ok', 'password="[redacted]" ok'],
  ['{"token":"abc123","n":1}', '{"token":"[redacted]","n":1}'],
  ["secrets are fine", "secrets are fine"],
  ["tokens: 5", "tokens: 5"],
  // pre-release review low: a path needs a dotted extension or a lowercase segment of 3+ letters (`xy` no longer counts).
  ["Ab12Cd34Ef56Gh78/xy/Ij90Kl12Mn34Op56", "[redacted]"],
  ["Ab12Cd34Ef56Gh78/Ij90Kl12Mn34Op56/abc", "Ab12Cd34Ef56Gh78/Ij90Kl12Mn34Op56/abc"],
  ["Ab12Cd34Ef56Gh78/Ij90Kl12Mn34/x.ts", "Ab12Cd34Ef56Gh78/Ij90Kl12Mn34/x.ts"],
  ["src/lib/util/Abcdefgh12345678Ijklmn", "src/lib/util/Abcdefgh12345678Ijklmn"],
];

describe("stripAbsolutePaths", () => {
  for (const [raw, want] of STRIP) it(JSON.stringify(raw), () => expect(stripAbsolutePaths(raw)).toBe(want));
});

describe("redactSecrets", () => {
  for (const [raw, want] of REDACT) it(JSON.stringify(raw), () => expect(redactSecrets(raw)).toBe(want));
});
