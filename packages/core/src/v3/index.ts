// Copyright 2026 Ix Infrastructure Inc.
//
// @peer2peer/core/v3: the Peer2Peer v3 client core (docs/protocol.md, draft 3
// with the Phase 2 additions). Pure: no network or Node-only APIs; the
// file-backed store is at @peer2peer/core/v3/node.
//
// Relay-facing API (packages/relay imports these): canonicalRelayUrl,
// relayAuthMessage, signRelayAuth, verifyRelayAuth, checkHelloRelay,
// verifyDeviceCertV3, parseOuterEnvelope, verifyOuterEnvelope,
// verifyCapForSend, powOk, verifyIdentityDocLink, peekIdentityDoc,
// docListsRelay. See ./relay.ts.

export { P2PError, fail, type RejectReason } from "../errors.js";
export { b32Decode, b32Encode, b64uDecode, b64uEncode } from "../encoding.js";
export { randomBytes, sha256 } from "../crypto.js";
// The strict Ed25519 checks, for consumers that verify signatures natively (the relay).
export { assertStrongEd25519PublicKey, assertStrongX25519PublicKey, clearVerifyMemo, ed25519Verify } from "../crypto.js";
export { REPLAY_MAX_AGE_MS_V3, REPLAY_FUTURE_SKEW_MS, REPLAY_WINDOW, sessionKey, type ReplayRecord, type ReplayVerdict } from "../replay.js";
export { MemoryDocBackend, type DocBackend } from "../docbackend.js";
export * from "./base.js";
export * from "./sanitize.js";
export * from "./relayurl.js";
export * from "./identity.js";
export * from "./device.js";
export * from "./identitydoc.js";
export * from "./link.js";
export * from "./proofs.js";
export * from "./signers.js";
export * from "./caps.js";
export * from "./friends.js";
export * from "./circles.js";
export * from "./roster.js";
export * from "./authz.js";
export * from "./envelope.js";
export {
  checkHelloRelay,
  docListsRelay,
  leadingZeroBits,
  MAX_POW_BITS,
  MAX_RELAY_FRAME_BYTES,
  parseOuterEnvelope,
  powOk,
  RELAY_AUTH_PREFIX,
  relayAuthMessage,
  signRelayAuth,
  solvePow,
  verifyOuterEnvelope,
  verifyRelayAuth,
  type OuterEnvelope,
  type RelayAuthParams,
  type VerifiedOuterEnvelope,
} from "./relay.js";
export * from "./store.js";
export * from "./state.js";
export * from "./incoming.js";
