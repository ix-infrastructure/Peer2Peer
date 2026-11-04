// Copyright 2026 Ix Infrastructure Inc.
//
// Every suite starts with "no Claude Code or Codex ancestor" (projects.ts agentAncestor), whatever
// runs the tests; a test about agents sets their variables, or the ancestry, itself.
import { setAgentAncestorForTests } from "../projects.js";

setAgentAncestorForTests(false);
