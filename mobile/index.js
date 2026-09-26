/**
 * App entry.
 *
 * 2026-09-26 audit H-3: the crypto/Buffer polyfills install FIRST, before
 * any app module loads. Roughly twenty src modules touch a bare `Buffer` at
 * module scope (e.g. unlockProof.ts's PROOF_PLAINTEXT, reached at import
 * time through store.tsx) and the crypto engine resolves
 * react-native-quick-crypto's native JSI addon — on a device, global.Buffer
 * and global.crypto exist only after QuickCrypto.install() runs. The entry
 * used to be 4 lines and installed nothing, so the first module-scope
 * Buffer access crashed the app at startup.
 *
 * require() (not ESM import) is deliberate: every import in this file would
 * be hoisted and evaluated BEFORE this module's body, so App's whole module
 * graph would still load before install() executed. Sequential requires keep
 * the install strictly first.
 */
const quickCryptoModule = require("react-native-quick-crypto");
const QuickCrypto = quickCryptoModule.default ?? quickCryptoModule;
QuickCrypto.install();

const { AppRegistry } = require("react-native");
const App = require("./App").default;

AppRegistry.registerComponent("MindPattern", () => App);
