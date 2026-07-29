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
//   Its Babel-8-based alternatives require Node >=22; when this config was
//   written the repo/CI ran Node 20 (CI has since moved to 22 — the undici-8
//   NODE_VERSION note in ci.yml). @babel/eslint-parser 7.x still works: it
//   parses TS/TSX *syntactically* (independent of the
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
      // Deliberately OFF, with the reasoning on record rather than 29
      // scattered warnings everyone learns to scroll past:
      //
      // Every data panel in this app uses the same on-mount fetch idiom —
      // an effect that kicks off an async request and calls setState when
      // it resolves, guarded by a `cancelled` flag on unmount. The rule
      // flags each of these, but its premise (setState-in-effect causes
      // cascading synchronous re-renders) targets the *synchronous* case;
      // the async resolve-then-set here renders once per fetch, which is
      // the intended behaviour and matches React's own data-fetching docs
      // absent a fetching library. Adopting one (react-query etc.) is a
      // product decision, not a lint fix.
      //
      // The other react-hooks rules stay ON and this file gates CI at
      // --max-warnings 0, so any NEW rule violation fails the build
      // instead of joining a drifting baseline.
      "react-hooks/set-state-in-effect": "off",
    },
  },
];
