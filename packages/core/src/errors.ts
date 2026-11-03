// Copyright 2026 Ix Infrastructure Inc.
//
// Typed rejection reasons. Every verifier in this package throws a P2PError
// carrying one of these; verifyIncoming() returns them as values.

export type RejectReason =
  // Structure / JWS envelope
  | "malformed"
  // An object lists a field this version doesn't understand in `crit` (docs/compatibility.md)
  | "unsupported-critical"
  | "bad-alg"
  | "typ-mismatch"
  | "kid-mismatch"
  // Kartr-signed objects
  | "unknown-kartr-key"
  | "kartr-signature-invalid"
  // Device-signed objects
  | "unknown-device"
  | "bad-signature"
  | "cert-mismatch"
  | "device-revoked"
  | "small-order-key"
  | "revocations-stale"
  // Time
  | "expired"
  | "not-yet-valid"
  // Friendship
  | "invite-mismatch"
  | "unknown-invite"
  | "invite-expired"
  | "audience-mismatch"
  | "invite-already-bound"
  | "self-friendship"
  // Roster
  | "stale-roster"
  | "roster-conflict"
  | "roster-session-mismatch"
  | "roster-owner-mismatch"
  | "no-roster"
  // A kind only a session's owner sends (status, idle, roster; §4.3) from someone else
  | "not-session-owner"
  // Envelope
  | "wrong-recipient"
  | "stale-timestamp"
  | "replayed-nonce"
  | "replayed-seq"
  | "replay-in-progress"
  | "gave-up"
  | "seq-too-old"
  | "decrypt-failed"
  | "workspace-mismatch"
  | "friendship-mismatch"
  // Authorisation (mayExchange)
  | "chain-invalid"
  | "not-participant"
  | "no-friendship"
  | "unfriended"
  // A roster's org without the owner's attestation in it (D9)
  | "owner-not-in-org"
  | "owner-workspace-mismatch"
  // ...the same, failed by the viewer (two-sided authorisation, C6)
  | "viewer-not-participant"
  | "viewer-no-friendship"
  | "viewer-unfriended"
  // --- v3 (docs/protocol.md, @peer2peer/core/v3) ---------------------------
  // Identity and device certificates (§2.1–§2.3)
  | "issuer-mismatch"
  | "did-mismatch"
  | "device-not-listed"
  | "identity-unknown"
  | "identity-fail-closed"
  | "blocked"
  // Identity documents (§2.5)
  | "chain-broken"
  | "merge-invalid"
  | "merge-adds-device"
  | "revoked-device-returned"
  // Linking, proofs, rotation (§2.4, §2.6, §2.8)
  | "link-mac-invalid"
  | "link-multiple-requests"
  | "proof-invalid"
  | "proof-unsupported"
  | "rotation-invalid"
  | "identity-rotated"
  // Circles (§3.3)
  | "circle-invalid"
  | "circle-chain-broken"
  | "circle-gap"
  | "circle-signer"
  | "circle-transfer"
  | "circle-final"
  | "circle-frozen"
  | "circle-owner-unavailable"
  | "not-admin"
  | "proposal-stale"
  | "proposal-duplicate"
  | "proposal-expired"
  | "proposal-refused"
  | "not-standing"
  | "viewer-not-standing"
  | "viewer-blocked"
  | "rate-limited"
  // Capabilities and relays (§5)
  | "cap-invalid"
  | "cap-denied"
  | "bad-relay-url"
  | "relay-mismatch"
  // A provisional result (a bundled document stood in for rule 6) used before re-verification
  | "provisional";

export class P2PError extends Error {
  readonly reason: RejectReason;
  constructor(reason: RejectReason, message?: string) {
    super(message ? `${reason}: ${message}` : reason);
    this.name = "P2PError";
    this.reason = reason;
  }
}

export function fail(reason: RejectReason, message?: string): never {
  throw new P2PError(reason, message);
}
