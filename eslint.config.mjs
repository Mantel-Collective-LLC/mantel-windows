import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["out/**", "dist/**", "dist-debug/**", "dist-fix/**", "dist-fix2/**", "dist-i18n/**", "dist-mac/**", "dist-mac-debug/**", "build/mac/**", "node_modules/**", "test/__snapshots__/**", "shared/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["ui/**/*.{ts,tsx}"],
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
    },
  },
  {
    files: ["dev/**/*.mjs", "scripts/**/*.mjs"],
    languageOptions: { globals: { process: "readonly", Buffer: "readonly", console: "readonly", setTimeout: "readonly", URL: "readonly", fetch: "readonly", window: "readonly", document: "readonly" } },
    rules: { "@typescript-eslint/no-unused-vars": ["error", { varsIgnorePattern: "^_", argsIgnorePattern: "^_", destructuredArrayIgnorePattern: "^_", ignoreRestSiblings: true }] },
  },
);
