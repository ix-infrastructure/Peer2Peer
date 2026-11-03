// Copyright 2026 Ix Infrastructure Inc.
//
// x:ix.note: an Ix session note shared with a peer session (SPEC.md §3).
// The receiver's agent may preview it; writing it into the receiver's graph
// is a separate action only the user can take (`p2p ix import`), after
// seeing it.

import { parseRepo, type RepoRef } from "./repo.js";
import {
  cleanMultiline,
  cps,
  fail,
  frame,
  isObj,
  jsonBytes,
  LIMITS,
  line,
  list,
  MAX_BODY_BYTES,
  NOTE_TAGS,
  oneOf,
  optStr,
  relPath,
  scrubPaths,
  toRepoRelative,
  type NoteTag,
  type O,
  type Roots,
} from "./text.js";

export const NOTE_KIND = "x:ix.note" as const;

export interface NoteBody {
  tag: NoteTag;
  text: string;
  title?: string;
  /** The sender's Ix session name (a label; nothing on the receiver resolves it). */
  session?: string;
  repo?: RepoRef;
  /** Repo-relative paths the note is about. */
  refs?: string[];
  /** When the note was written (ISO 8601). */
  at?: string;
}

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2})$/;

/** Validates a received (or about-to-be-sent) note body. Unknown fields are dropped. */
export function parseNoteBody(v: unknown): NoteBody {
  if (!isObj(v)) return fail("note body must be an object");
  const o = v as O;
  if (jsonBytes(o) > MAX_BODY_BYTES) fail(`note body is larger than ${MAX_BODY_BYTES} bytes`);
  const tag = oneOf(o, "tag", NOTE_TAGS, "note");
  if (typeof o.text !== "string") fail("note.text must be a string");
  const text = cleanMultiline(o.text as string);
  if (text === "") fail("note.text is empty");
  if (Buffer.byteLength(text, "utf8") > LIMITS.noteText) fail(`note.text is larger than ${LIMITS.noteText} bytes`);
  const title = optStr(o, "title", LIMITS.title, "note");
  const session = optStr(o, "session", LIMITS.session, "note");
  const repo = o.repo === undefined ? undefined : parseRepo(o.repo, "note.repo");
  const refs = list(o, "refs", LIMITS.refs, "note", (x, i) => relPath(x, `note.refs[${i}]`));
  const at = optStr(o, "at", 40, "note");
  if (at !== undefined && !ISO_RE.test(at)) fail("note.at must be an ISO 8601 time");
  return {
    tag,
    text,
    ...(title ? { title } : {}),
    ...(session ? { session } : {}),
    ...(repo ? { repo } : {}),
    ...(refs.length ? { refs } : {}),
    ...(at ? { at } : {}),
  };
}

export function noteFallback(b: Pick<NoteBody, "tag">): string {
  const what = b.tag === "note" ? "an Ix note" : `an Ix ${b.tag} note`;
  return `shared ${what}: install Ix to open it: https://github.com/ix-infrastructure/Ix`;
}

export interface NoteInput {
  text: string;
  tag?: string;
  title?: string;
  session?: string;
  refs?: string[];
  repo?: RepoRef;
  at?: string;
  /** For scrubbing: the repo root and home directory (never sent). */
  root?: Roots;
  home?: string;
  hostname?: string;
}

/** Sending: a validated body and its fallback, with local paths scrubbed and refs made repo-relative. */
export function buildNote(i: NoteInput): { body: NoteBody; fallback: string } {
  const tag = (NOTE_TAGS as readonly string[]).includes(i.tag ?? "note") ? ((i.tag ?? "note") as NoteTag) : fail(`--tag must be one of ${NOTE_TAGS.join(", ")}`);
  const scrub = (s: string) => scrubPaths(s, { root: i.root, home: i.home, hostname: i.hostname });
  const refs = (i.refs ?? []).map((r) => toRepoRelative(r, i.root)).filter((r): r is string => r !== undefined);
  const raw: O = {
    tag,
    text: scrub(i.text),
    ...(i.title ? { title: scrub(i.title).trim().slice(0, LIMITS.title) } : {}),
    ...(i.session ? { session: scrub(i.session).trim().slice(0, LIMITS.session) } : {}),
    ...(i.repo ? { repo: i.repo } : {}),
    ...(refs.length ? { refs: [...new Set(refs)].slice(0, LIMITS.refs) } : {}),
    ...(i.at ? { at: i.at } : {}),
  };
  const body = parseNoteBody(raw);
  return { body, fallback: noteFallback(body) };
}

/** Receiving: the model-safe digest, framed as data from the named peer. */
export function renderNote(b: NoteBody, from: { address: string }): Record<string, unknown> {
  const text = line(b.text, LIMITS.digestText);
  const truncated = cps(line(b.text, LIMITS.noteText)) > cps(text);
  const head = [b.title ? `"${line(b.title, LIMITS.title)}"` : undefined, b.session ? `from Ix session ${line(b.session, LIMITS.session)}` : undefined].filter(Boolean).join(" ");
  return {
    type: "note",
    tag: b.tag,
    ...(b.title ? { title: line(b.title, LIMITS.title) } : {}),
    ...(b.session ? { session: line(b.session, LIMITS.session) } : {}),
    ...(b.repo ? { repo: b.repo } : {}),
    ...(b.refs ? { refs: b.refs } : {}),
    ...(b.at ? { at: b.at } : {}),
    text,
    ...(truncated ? { truncated: true } : {}),
    digest: frame(from.address, `Ix ${b.tag} note`, `${head ? `${head}: ` : ""}${text}${truncated ? " …" : ""}`),
    consent: "Preview only. It is written into the local Ix graph only if the user runs `p2p ix import <event id>` themselves.",
  };
}
