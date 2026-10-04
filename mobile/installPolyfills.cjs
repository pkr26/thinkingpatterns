/**
 * Install the native crypto backend's Buffer and crypto globals.
 * index.js requires this module before App because application modules can
 * access Buffer during initialization. Keep installation synchronous.
 */
const quickCryptoModule = require("react-native-quick-crypto");
const QuickCrypto = quickCryptoModule.default ?? quickCryptoModule;
QuickCrypto.install();
