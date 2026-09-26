/**
 * 2026-09-26 audit H-3: the standard React Native babel config (the repo
 * shipped none — `react-native start` only worked through Metro's built-in
 * defaults). The preset compiles JSX with the automatic runtime
 * ({runtime: 'automatic'} in @react-native/babel-preset 0.87), matching the
 * tsconfig's "jsx": "react-jsx" — no legacy createReactClass calls exist in
 * src/. The .cjs extension is required: package.json sets "type": "module"
 * (for vitest), under which a .js config would load as ESM and fail on
 * module.exports. Vitest is unaffected: it transforms through Vite/Oxc
 * (see vitest.config.ts), never through this file.
 */
module.exports = {
  presets: ["module:@react-native/babel-preset"],
};
