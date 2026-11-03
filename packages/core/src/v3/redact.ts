// Copyright 2026 Ix Infrastructure Inc.
//
// Path and secret scrubbing for one-line texts a client composes from local
// context and shares (a subagent's task line). No imports: the Claude mod
// ships a byte-for-byte copy at mods/claude/peer2peer/hooks/redact.ts, which
// scripts/check-bundle.sh verifies, so the two can't drift.

/**
 * What may come right before a path: the start, a space, or an opening or
 * separating character (`[ { ( < : , " ' \` = ; | * @ ! -`, and smart quotes).
 */
const PATH_LEAD = "(^|[\\s\\[{(<:,\"'`=;|*@!\\-\u201C\u201D\u2018\u2019])";
/**
 * The start of an absolute or home path: `scheme:///`, `~/`, `~\`, `~user/`,
 * a lone `/` or `\` (not `//`, so `https://host` stays), a drive (`C:\`,
 * `C:/`), a UNC `\\server`, `$HOME/` or `%VAR%\`.
 */
const PATH_START = "(?:[A-Za-z][A-Za-z0-9+.-]*:\\/\\/\\/|~[A-Za-z0-9._-]*[\\\\/]|\\/(?!\\/)|\\\\\\\\|\\\\(?!\\\\)|[A-Za-z]:[\\\\/]|\\$HOME[\\\\/]|%[A-Za-z_]+%[\\\\/])";
const PATH_RE = new RegExp(`${PATH_LEAD}(${PATH_START}[^\\s)\\]}>"'\`,;]*)`, "g");
/** A slash command (`/peers`, `/review`): one lowercase word, kept. */
const SLASH_COMMAND = /^\/[a-z][a-z0-9_-]*$/;

/**
 * `text` without absolute or home paths (POSIX, Windows, UNC, `~user`,
 * `$HOME`, `%VAR%`, `file:///`), wherever one starts after a space or an
 * opening or separating character. Repo-relative names, URLs with a host,
 * and slash commands like `/peers` stay.
 */
export function stripAbsolutePaths(text: string): string {
  return text
    .replace(PATH_RE, (m: string, lead: string, path: string) => (SLASH_COMMAND.test(path) ? m : lead))
    .replace(/\s+/g, " ")
    .replace(/\s+([.,;:])/g, "$1")
    .trim();
}

const SECRET_PATTERNS: readonly RegExp[] = [
  /-----BEGIN[\s\S]*/g,
  /\bsk-[A-Za-z0-9_-]{12,}/g,
  /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bglpat-[A-Za-z0-9_-]{20,}/g,
  /\bxox[abpe]-[A-Za-z0-9.-]{10,}/g,
  /\bxapp-[A-Za-z0-9-]{10,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bAIza[0-9A-Za-z_-]{30,}/g,
  /\bGOCSPX-[A-Za-z0-9_-]{10,}/g,
  /\beyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]{4,}){1,2}/g,
];
/** `password=x`, `api_key: x`, and JSON's `"password": "x"` (a quoted value is redacted whole, its quotes kept). */
const KEYWORD_SECRET = /(?<![A-Za-z])(password|passwd|secret|token|api[_-]?key)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s"']+)/gi;
const BEARER = /\bBearer\s+\S{8,}/gi;
const HEX_RUN = /\b[0-9a-fA-F]{32,}\b/g;
const LONG_RUN = /[A-Za-z0-9+/_=.-]{32,}/g;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const isGitSha = (m: string) => /^[0-9a-fA-F]+$/.test(m) && (m.length === 40 || m.length === 64);

/** Whether a 32+ run is a path or a file name rather than a secret. */
function isPathLike(run: string): boolean {
  if (/[+=]/.test(run)) return false;
  const segs = run.split(/[/.]/).filter(Boolean);
  if (segs.length < 2 || segs.some((s) => s.length > 24)) return false;
  // At least one plain lowercase word of 3 or more letters as a segment, or a dotted extension.
  return run.split("/").some((s) => /^[a-z]{3,}$/.test(s) || /\.[A-Za-z0-9]{1,8}$/.test(s));
}

/**
 * `text` with common secret shapes replaced by `[redacted]`: URL userinfo,
 * keyword secrets (`password=`, `passwd:`, `secret=`, `token:`, `api_key=`)
 * and `Bearer` tokens, provider keys and tokens, PEM blocks, JWTs, and long
 * hex or base64-like runs. Git SHAs (40 or 64 hex), UUIDs and paths stay.
 */
export function redactSecrets(text: string): string {
  let out = text.replace(/([A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/@]+@/g, "$1[redacted]@");
  // Keyword secrets (`password=…`, `api_key: …`, `token=…`) and bearer tokens: the value goes, the keyword stays.
  out = out.replace(BEARER, (m: string) => `${m.slice(0, 6)} [redacted]`);
  out = out.replace(KEYWORD_SECRET, (_m: string, key: string, sep: string, value: string) => {
    const q = value[0] === '"' || value[0] === "'" ? value[0] : "";
    return `${key}${sep}${q}[redacted]${q}`;
  });
  for (const re of SECRET_PATTERNS) out = out.replace(re, "[redacted]");
  out = out.replace(HEX_RUN, (m) => (isGitSha(m) ? m : "[redacted]"));
  return out.replace(LONG_RUN, (m) => {
    if (isGitSha(m) || UUID.test(m) || isPathLike(m)) return m;
    return /[0-9]/.test(m) && /[A-Za-z]/.test(m) ? "[redacted]" : m;
  });
}
