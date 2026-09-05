/**
 * Vitest engine: the app's engine.ts resolves react-native-quick-crypto via
 * require(), which does not exist under vitest's ESM transform. Vitest
 * aliases every `./engine` import to THIS module instead — same structural
 * interface, backed by node:crypto. Tests therefore execute the real
 * kdf.ts/envelope.ts/aad.ts shipping code.
 */
import crypto from "node:crypto";

export const engine = crypto as unknown as import("../../src/crypto/engine").CryptoEngine;
