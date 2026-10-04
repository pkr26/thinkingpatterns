import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Vite uses Oxc to transform the automatic JSX runtime.
  oxc: { jsx: { runtime: "automatic" } },
  test: {
    environment: "node",
    include: ["tests/**/*.test.{ts,tsx}"],
    // Deterministic English for the suite's shipped-copy assertions; the
    // device locale of the machine running the tests must not leak in.
    setupFiles: ["tests/helpers/i18nSetup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      // Native-only branches need device verification in addition to this
      // Node suite. Keep global coverage and stricter security-module floors.
      thresholds: {
        statements: 90,
        branches: 85,
        functions: 85,
        lines: 90,
        // Guard safety and crypto modules against coverage regressions.
        "src/crisisDetect.ts": { lines: 98 },
        "src/questionFeedback.ts": { lines: 90 },
        "src/strings.ts": { lines: 90 },
        "src/rotation.ts": { lines: 85 },
        "src/crypto/aad.ts": { lines: 95 },
        "src/crypto/envelope.ts": { lines: 95 },
        "src/crypto/kdf.ts": { lines: 95 },
      },
    },
  },
  resolve: {
    alias: [
      // Execute the REAL crypto modules with node:crypto behind the same
      // engine interface (see tests/helpers/nodeEngine.ts).
      {
        find: /^\.\/engine$/,
        replacement: fileURLToPath(new URL("./tests/helpers/nodeEngine.ts", import.meta.url)),
      },
      {
        find: /^@react-native-async-storage\/async-storage$/,
        replacement: fileURLToPath(new URL("./tests/helpers/storageMock.ts", import.meta.url)),
      },
      // Native modules do not load under a plain node runtime; the mocks
      // keep the exact API surface the app touches.
      {
        find: /^react-native$/,
        replacement: fileURLToPath(new URL("./tests/helpers/rnMock.tsx", import.meta.url)),
      },
      {
        find: /^react-native-quick-crypto$/,
        replacement: fileURLToPath(new URL("./tests/helpers/quickCryptoMock.ts", import.meta.url)),
      },
      {
        find: /^react-native-keychain$/,
        replacement: fileURLToPath(new URL("./tests/helpers/keychainMock.ts", import.meta.url)),
      },
      // Match the Expo interfaces used by recording, storage, and sharing.
      {
        find: /^expo-audio$/,
        replacement: fileURLToPath(new URL("./tests/helpers/expoAudioMock.ts", import.meta.url)),
      },
      {
        find: /^expo-sharing$/,
        replacement: fileURLToPath(new URL("./tests/helpers/expoSharingMock.ts", import.meta.url)),
      },
      {
        find: /^expo-file-system(\/legacy)?$/,
        replacement: fileURLToPath(new URL("./tests/helpers/expoFsMock.ts", import.meta.url)),
      },
      {
        find: /^@react-navigation\/native-stack$/,
        replacement: fileURLToPath(new URL("./tests/helpers/navigationStackMock.tsx", import.meta.url)),
      },
    ],
  },
});
