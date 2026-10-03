/**
 * App entry.
 *
 * 2026-09-26 audit H-3: the crypto/Buffer polyfills install FIRST, before
 * any app module loads — see installPolyfills.cjs for the full rationale
 * (roughly twenty src modules touch a bare `Buffer` at module scope, and
 * global.Buffer/global.crypto exist on a device only after
 * QuickCrypto.install() runs). The entry used to be 4 lines and installed
 * nothing, so the first module-scope Buffer access crashed the app at
 * startup.
 *
 * require() (not ESM import) is deliberate: every import in this file would
 * be hoisted and evaluated BEFORE this module's body, so App's whole module
 * graph would still load before install() executed. Sequential requires keep
 * the install strictly first — the polyfill require MUST stay above the
 * ./App require (tests/bootstrap.test.ts pins that order).
 */
require("./installPolyfills.cjs"); // installs global Buffer/crypto (H-3)

const { AppRegistry } = require("react-native");
const App = require("./App").default;

AppRegistry.registerComponent("MindPattern", () => App);
