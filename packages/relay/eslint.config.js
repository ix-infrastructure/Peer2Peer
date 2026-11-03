// Copyright 2026 Ix Infrastructure Inc.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";
import unusedImports from "eslint-plugin-unused-imports";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "coverage/**", "eslint.config.js"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  prettier,
  {
    plugins: { "unused-imports": unusedImports },
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "unused-imports/no-unused-imports": "error",
      "unused-imports/no-unused-vars": [
        "error",
        { vars: "all", varsIgnorePattern: "^_", args: "after-used", argsIgnorePattern: "^_", caughtErrors: "none" },
      ],
      // Best-effort cleanup (e.g. removing a temp file) uses empty catches.
      "no-empty": ["error", { allowEmptyCatch: true }],
      // Control-character regexes validate addresses and cursor values.
      "no-control-regex": "off",
    },
  },
);
