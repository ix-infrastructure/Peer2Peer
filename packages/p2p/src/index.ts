// Copyright 2026 Ix Infrastructure Inc.
//
// @peer2peer/cli: the standalone `p2p` CLI for Peer2Peer v3. The binary is
// `p2p` (./bin.ts); this entry point exposes the pieces for embedding and
// tests: the relay client, the App context and the command functions.

export * from "./relay-client.js";
export * from "./config.js";
export * from "./errors.js";
export { App, type Io, type AppOptions, type Delivery } from "./app.js";
export { buildProgram, main, realOps, VERSION } from "./cli.js";
export { processEnvelope, receiving } from "./inbound.js";
// The extension seam (extensions.ts): the contract an @peer2peer/ext-* package implements.
export * from "./extensions.js";
export { sendExtension, MAX_EXT_PLAINTEXT_BYTES, type SendExtOpts } from "./sessions.js";
