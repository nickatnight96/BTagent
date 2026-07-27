// Flat ESLint config for the BTagent frontend (#381).
//
// Before this, `npm run lint` ran `eslint .` with no eslint installed and no
// config, so it printed "command not found" and exited 0 — a vacuous gate.
// This config makes `npm run lint` actually run: it parses the .ts/.tsx source
// and runs the react-hooks rules, returning a real exit code.
//
// Parser choice — why NOT typescript-eslint:
//   typescript-eslint (the usual TS ESLint parser) hard-throws at load time
//   against this repo's TypeScript 7.x ("typescript-eslint does not support
//   TS 7.0", see https://github.com/typescript-eslint/typescript-eslint/issues/10940).
//   Its Babel-8-based alternatives require Node >=22, but the repo/CI run on
//   Node 20. @babel/eslint-parser 7.x is the combination that actually works on
//   Node 20 + TS 7: it parses TS/TSX *syntactically* (independent of the
//   installed `typescript` version) so the lint runs today. It is not
//   type-aware — full type checking is already gated separately by `tsc`
//   (the `typecheck` / `build:strict` scripts and the CI "Frontend" job).
//   Revisit and switch to typescript-eslint once it supports TS 7 (paired with
//   an ESLint/Node combo that still resolves cleanly).
//
// Findings are surfaced as WARNINGS, not errors, so this freshly-introduced
// gate runs to completion with a real exit code (0 when only warnings are
// present) instead of hard-failing on the codebase's pre-existing issues.
// Tighten individual rules to "error" as the code is cleaned up.

import globals from "globals";
import babelParser from "@babel/eslint-parser";
import reactHooks from "eslint-plugin-react-hooks";

// Downgrade the react-hooks recommended rule set from "error" to "warn" for the
// introductory gate (see header note).
const reactHooksWarn = Object.fromEntries(
  Object.keys(reactHooks.configs["recommended-latest"].rules).map((rule) => [rule, "warn"]),
);

export default [
  {
    // Build output, deps, coverage, and tooling config files are not app source.
    ignores: [
      "dist/**",
      "node_modules/**",
      "coverage/**",
      ".venv/**",
      "**/*.config.js",
      "**/*.config.ts",
    ],
  },
  {
    files: ["**/*.{ts,tsx,js,jsx}"],
    languageOptions: {
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          presets: [
            // Babel 8 removed `isTSX` / `allExtensions`. They forced every
            // file to be parsed as TSX; the replacement is Babel's own
            // extension-based detection, which is what we actually want —
            // JSX lives only in .tsx/.jsx here, and parsing a .ts file as
            // TSX makes `<T>` ambiguous between a cast and a JSX element.
            "@babel/preset-typescript",
            ["@babel/preset-react", { runtime: "automatic" }],
          ],
        },
      },
      globals: {
        ...globals.browser,
        ...globals.es2021,
      },
    },
    plugins: {
      "react-hooks": reactHooks,
    },
    rules: {
      ...reactHooksWarn,
    },
  },
];
