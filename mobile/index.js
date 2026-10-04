/**
 * Install Buffer and crypto before loading the application module graph.
 * Sequential require calls preserve this order; ESM imports would be hoisted
 * before the installer runs. tests/bootstrap.test.ts verifies the contract.
 */
require("./installPolyfills.cjs"); // installs global Buffer/crypto (H-3)

const { AppRegistry } = require("react-native");
const App = require("./App").default;

AppRegistry.registerComponent("MindPattern", () => App);
