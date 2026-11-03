// Copyright 2026 Ix Infrastructure Inc.
//
// @peer2peer/ext-ix: the Ix extension for Peer2Peer v3 (SPEC.md). `p2p`
// loads `extension` when this package is installed; the rest is the library
// (send helpers that build bodies from Ix output, receive helpers that
// validate, sanitize and render, and semantic-conflict detection) for other
// clients such as the Claude Code mod.

export { extension, createIxExtension, receiveIx, ixCommands, KINDS, VERSION, type Deps } from "./extension.js";
export { NOTE_KIND, parseNoteBody, buildNote, renderNote, noteFallback, type NoteBody, type NoteInput } from "./note.js";
export {
  SUBGRAPH_KIND,
  parseSubgraphBody,
  parseSelector,
  buildSubgraph,
  renderSubgraph,
  subgraphFallback,
  resolveArgv,
  describeSelector,
  splitPattern,
  type SubgraphBody,
  type Selector,
  type SubgraphInput,
} from "./subgraph.js";
export { IMPACT_KIND, parseImpactBody, buildImpact, renderImpact, impactFallback, type ImpactBody, type ImpactInput, type ImpactSymbol, type ImpactComponent } from "./impact.js";
export { semanticConflicts, ixNeighbourhood, parseAround, type SemanticConflict, type PeerChanges, type Neighbourhood, type NeighbourhoodFn, type Relation, type ConflictOptions } from "./conflicts.js";
export { ixRunner, ixAvailable, ixJson, type IxRunner, type IxResult } from "./ix.js";
export { normalizeRemote, parseRepo, localRepo, compareRepo, type RepoRef, type LocalRepo } from "./repo.js";
export { SPEC_VERSION, MAX_BODY_BYTES, LIMITS, NOTE_TAGS, RISK_LEVELS, InvalidBody, IxExtError, toRepoRelative, scrubPaths, type NoteTag, type RiskLevel } from "./text.js";
export {
  FOOTPRINT_KIND,
  FOOTPRINT_TTL,
  MAX_FOOTPRINT_BYTES,
  FP_LIMITS,
  parseFootprintBody,
  assembleFootprint,
  footprintFallback,
  footprintDigest,
  symbolKey,
  wireQualifiedKey,
  type FootprintBody,
  type FpActor,
  type FpComponent,
  type RawActor,
} from "./footprint.js";
export { computeFootprint, parseUnifiedDiff, groupRanges, parseWorktrees, declaredNames, type ComputeInput, type ComputeDeps, type ComputeResult } from "./footprint-compute.js";
export { footprintNames, FOOTPRINT_MIN_INTERVAL_MS, FOOTPRINT_KEEPALIVE_MS, type FootprintConfig } from "./footprint-command.js";
export { deriveNameKey, pickRootCommit, hashFile, hashSymbol, hashRegion, type NameKey } from "./hmac.js";
export { computeOverlaps, OVERLAP_TIERS, type Overlap, type OverlapPeer, type OverlapTier, type OverlapSeverity, type OverlapDirection } from "./overlap.js";
