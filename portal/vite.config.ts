import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "node",
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/helpers/setup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.tsx is the DOM-only entry point (react-dom render); it has no
      // testable logic and no node-runnable renderer.
      exclude: ["src/main.tsx"],
      thresholds: { statements: 85, branches: 80, functions: 85, lines: 85, perFile: true },
    },
  },
  server: {
    // Dev proxy: same-origin /api against the local backend — no CORS
    // configuration needed during development.
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
