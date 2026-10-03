/** Metro resolves this native entry before engine.ts. A static import is
 * essential: dynamic module lookups do not receive a Metro module ID.
 * Native initialization errors must remain visible; a device cannot use
 * the Node backend supplied to command-line tools and tests. */
import QuickCrypto from "react-native-quick-crypto";
import type { CryptoEngine } from "./engine";

export const engine: CryptoEngine = QuickCrypto as unknown as CryptoEngine;
