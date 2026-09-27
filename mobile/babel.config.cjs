/**
 * 2026-09-26 audit H-3: the standard React Native babel config (the repo
 * shipped none — `react-native start` only worked through Metro's built-in
 * defaults). The preset compiles JSX with the automatic runtime
 * ({runtime: 'automatic'} in @react-native/babel-preset 0.87), matching the
 * tsconfig's "jsx": "react-jsx" — no legacy createReactClass calls exist in
 * src/. The .cjs extension is required: package.json sets "type": "module"
 * (for vitest), under which a .js config would load as ESM and fail on
 * require()/module.exports. Vitest is unaffected: it transforms through
 * Vite/Oxc (see vitest.config.ts), never through this file.
 *
 * 2026-09-26 audit LOW (SettingsScreen APP_VERSION): one build-time
 * constant. The plugin below inlines the `__APP_VERSION__` identifier as
 * the package.json version string at bundle time — the established
 * minimal RN idiom (transform-inline style, no new dependency). The
 * identifier is declared (`declare const`) where src/ reads it, and the
 * vitest environment defines the same global from the same manifest (see
 * tests/helpers/i18nSetup.ts), so the About line can never drift from
 * package.json again.
 */
const pkg = require("./package.json");

/** Replace value-position reads of __APP_VERSION__ with the manifest
 *  version literal. Property positions (object keys, non-computed member
 *  accesses) are skipped so the transform never rewrites unrelated code. */
function appVersionInline({ types }) {
  return {
    name: "mindpattern-app-version-inline",
    visitor: {
      Identifier(path) {
        if (path.node.name !== "__APP_VERSION__") return;
        const parent = path.parent;
        if (types.isMemberExpression(parent) && parent.property === path.node && !parent.computed) return;
        if (types.isObjectProperty(parent) && parent.key === path.node) return;
        path.replaceWith(types.stringLiteral(pkg.version));
      },
    },
  };
}

module.exports = {
  presets: ["module:@react-native/babel-preset"],
  plugins: [appVersionInline],
};
