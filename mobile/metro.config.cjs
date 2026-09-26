/**
 * 2026-09-26 audit H-3: the standard Metro config for the installed
 * @react-native/metro-config 0.87.1 (the repo previously shipped none, so
 * `react-native start` relied on Metro's implicit defaults). The RN default
 * brings the platform resolver fields, the react-native/setup-env pre-main
 * module, and the JS polyfills set. No app-specific overrides are needed;
 * this file exists so the toolchain is explicit and future overrides have
 * a home. The .cjs extension is required: package.json sets "type":
 * "module" (for vitest), under which a .js config would load as ESM and
 * fail on require()/module.exports. Vitest never loads this file (see
 * vitest.config.ts).
 */
const { getDefaultConfig, mergeConfig } = require("@react-native/metro-config");

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
const config = {};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
