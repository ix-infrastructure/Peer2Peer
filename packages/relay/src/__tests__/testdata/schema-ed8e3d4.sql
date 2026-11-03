-- The relay SQLite schema exactly as at main ed8e3d4 (the build deployed on the
-- team tailnet), extracted from packages/relay/src/sqlite-store.ts at that commit.
-- Used by schema-upgrade.test.ts to prove later builds open it without data loss.
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
  did TEXT PRIMARY KEY,
  iss TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  evictable INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS devices_seen ON devices (last_seen);
CREATE INDEX IF NOT EXISTS devices_evictable ON devices (last_seen, did) WHERE evictable = 1;
CREATE TABLE IF NOT EXISTS envelopes (
  rid INTEGER PRIMARY KEY AUTOINCREMENT,
  mbox_to TEXT NOT NULL,
  mbox_did TEXT NOT NULL,
  src TEXT NOT NULL,
  size INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  env TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS envelopes_mbox ON envelopes (mbox_to, mbox_did, rid);
CREATE INDEX IF NOT EXISTS envelopes_time ON envelopes (received_at);
CREATE INDEX IF NOT EXISTS envelopes_src_mbox ON envelopes (src, mbox_to, mbox_did, rid);
CREATE INDEX IF NOT EXISTS envelopes_to_src ON envelopes (mbox_to, src, rid);
CREATE TABLE IF NOT EXISTS totals (
  kind TEXT NOT NULL,
  key TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  n INTEGER NOT NULL,
  PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS totals_bytes ON totals (kind, bytes);
CREATE TABLE IF NOT EXISTS caps (
  key TEXT PRIMARY KEY,
  revoked INTEGER NOT NULL DEFAULT 0,
  uses INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS caps_time ON caps (updated_at);
CREATE TABLE IF NOT EXISTS identity_docs (
  hash TEXT PRIMARY KEY,
  iss TEXT NOT NULL,
  ver INTEGER NOT NULL,
  prev TEXT,
  merge TEXT,
  devices TEXT NOT NULL,
  iat INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  jws TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_iss ON identity_docs (iss, ver);
CREATE INDEX IF NOT EXISTS identity_prev ON identity_docs (prev);
CREATE INDEX IF NOT EXISTS identity_merge ON identity_docs (merge);
CREATE TABLE IF NOT EXISTS identity_index (
  iss TEXT PRIMARY KEY,
  head TEXT NOT NULL,
  head_ver INTEGER NOT NULL,
  head_exp INTEGER NOT NULL,
  tips TEXT NOT NULL,
  allowed TEXT NOT NULL,
  cap TEXT,
  left_at INTEGER
);
CREATE INDEX IF NOT EXISTS identity_index_exp ON identity_index (head_exp);
CREATE INDEX IF NOT EXISTS identity_index_left ON identity_index (left_at);
CREATE TABLE IF NOT EXISTS allowed_devices (
  did TEXT NOT NULL,
  iss TEXT NOT NULL,
  PRIMARY KEY (did, iss)
);
CREATE INDEX IF NOT EXISTS allowed_devices_iss ON allowed_devices (iss);
CREATE TABLE IF NOT EXISTS identity_seen (
  iss TEXT NOT NULL,
  did TEXT NOT NULL,
  at INTEGER NOT NULL,
  PRIMARY KEY (iss, did)
);
CREATE INDEX IF NOT EXISTS identity_seen_at ON identity_seen (at);
DROP TABLE IF EXISTS identity_revoked;
DROP TABLE IF EXISTS retired_devices;
