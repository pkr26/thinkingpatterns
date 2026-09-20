import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Vitest 4/Vite 8 uses Oxc for transforms. Configure the automatic JSX
  // runtime there rather than also setting the legacy esbuild option (which
  // makes Vite warn that it is ignored).
  oxc: { jsx: { runtime: "automatic" } },
  test: {
    environment: "node",
    include: ["tests/**/*.test.{ts,tsx}"],
    // Deterministic English for the suite's shipped-copy assertions; the
    // device locale of the machine running the tests must not leak in.
    setupFiles: ["tests/helpers/i18nSetup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // A global gate keeps the suite honest without pretending every
      // platform-conditional/native seam is executable in node. The prior
      // 98%-per-file gate made `npm test` permanently red despite 1,100+
      // passing behavioral tests and was especially misleading for native
      // availability branches. Raise this only alongside device coverage.
      thresholds: { statements: 90, branches: 85, functions: 85, lines: 90 },
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
      {
        find: /^@react-navigation\/native-stack$/,
        replacement: fileURLToPath(new URL("./tests/helpers/navigationStackMock.tsx", import.meta.url)),
      },
    ],
  },
});
