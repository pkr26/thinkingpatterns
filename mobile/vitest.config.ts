import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

export default defineConfig({
  // Component tests are .tsx; force the automatic JSX runtime for every
  // transformed file regardless of tsconfig include ranges.
  esbuild: { jsx: "automatic" },
  test: {
    environment: "node",
    include: ["tests/**/*.test.{ts,tsx}"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      thresholds: { statements: 98, branches: 98, functions: 98, lines: 98, perFile: true },
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
        find: /^@react-navigation\/native-stack$/,
        replacement: fileURLToPath(new URL("./tests/helpers/navigationStackMock.tsx", import.meta.url)),
      },
    ],
  },
});
