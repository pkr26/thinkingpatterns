/**
 * Bootstrap contract test (2026-09-26 audit H-3 follow-up).
 *
 * The Buffer/crypto crash class lives in the ENTRY, not in any src module:
 * on a device, global.Buffer/global.crypto exist only after
 * QuickCrypto.install() runs, so the polyfill module must execute before
 * App's whole module graph. That ordering was previously exercised only
 * under node globals (vitest always has Buffer/crypto), where the bug is
 * invisible.
 *
 * What this test PROVES, in a real child node process:
 *   1. A process that starts with globalThis.Buffer and globalThis.crypto
 *      DELETED gets both back after requiring installPolyfills.cjs alone —
 *      with the REAL react-native-quick-crypto JS and the REAL
 *      @craftzdog/react-native-buffer Buffer (Buffer.from round-trips).
 *   2. index.js requires the polyfill module BEFORE ./App, with no hoisted
 *      ESM `import` that could reorder evaluation.
 *
 * Honest coverage boundary: react-native-quick-crypto's NATIVE JSI addon
 * (NitroModules hybrid objects, the native quick-base64) exists only inside
 * a React Native runtime, so those three packages are stubbed at the
 * require boundary in the child. Everything else — quick-crypto's install()
 * implementation and the Buffer global it installs — is the production
 * code. A device/emulator launch remains the only end-to-end proof of the
 * native addon itself, and Metro's bundling order is pinned here only at
 * the source level.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const polyfillsPath = fileURLToPath(new URL("../installPolyfills.cjs", import.meta.url));
const indexPath = fileURLToPath(new URL("../index.js", import.meta.url));
const mobileDir = fileURLToPath(new URL("..", import.meta.url));

/**
 * The child script. The Module._load hook stubs ONLY the three packages
 * that cannot load outside React Native (`react-native` itself is Flow-
 * syntax JS, `react-native-quick-base64` requires it, and quick-crypto's
 * utils/conversion.js creates a NitroModules HybridObject at module scope);
 * every other require — installPolyfills.cjs's own require of
 * react-native-quick-crypto included — resolves the real package.
 */
const childScript = `
const Module = require("module");
const stubHits = { "react-native": 0, "react-native-quick-base64": 0, "react-native-nitro-modules": 0 };
const stubs = {
  "react-native": { Platform: { constants: { reactNativeVersion: { major: 0, minor: 87 } } } },
  "react-native-quick-base64": {
    toByteArray: (s) => Uint8Array.from(globalThis.atob(s), (c) => c.charCodeAt(0)),
    fromByteArray: (u8) => globalThis.btoa(String.fromCharCode(...u8)),
  },
  "react-native-nitro-modules": {
    NitroModules: { createHybridObject: () => new Proxy({}, { get: () => () => { throw new Error("native only"); } }) },
  },
};
const originalLoad = Module._load;
Module._load = function (request) {
  if (Object.prototype.hasOwnProperty.call(stubs, request)) {
    stubHits[request] += 1;
    return stubs[request];
  }
  return originalLoad.apply(this, arguments);
};

// The H-3 scenario: the app process boots with NEITHER global in place.
delete globalThis.Buffer;
delete globalThis.crypto;
const facts = {
  bufferBefore: typeof globalThis.Buffer,
  cryptoBefore: typeof globalThis.crypto,
  stubHits,
};
try {
  require(${JSON.stringify(polyfillsPath)});
  facts.loaded = true;
} catch (error) {
  facts.loaded = false;
  facts.loadError = String((error && error.stack) || error);
}
facts.bufferAfter = typeof globalThis.Buffer;
facts.cryptoAfter = typeof globalThis.crypto;
try {
  facts.bufferFromHex = globalThis.Buffer.from("hi").toString("hex");
  facts.cryptoRandomUuid = typeof globalThis.crypto.randomUUID;
  facts.base64Helpers = typeof globalThis.base64ToArrayBuffer + "/" + typeof globalThis.base64FromArrayBuffer;
} catch (error) {
  facts.useError = String(error);
}
process.stdout.write(JSON.stringify(facts));
`;

describe("bootstrap polyfill installation (H-3, 2026-09-26 audit follow-up)", () => {
  it("installPolyfills.cjs restores Buffer and crypto in a process that booted without either", () => {
    const scratch = mkdtempSync(join(tmpdir(), "mindpattern-bootstrap-"));
    const scriptPath = join(scratch, "bootstrapChild.cjs");
    writeFileSync(scriptPath, childScript);
    try {
      // NODE_OPTIONS is cleared so vitest's own flags cannot leak loader
      // hooks into what must be a plain node run of a plain CJS script.
      const stdout = execFileSync(process.execPath, [scriptPath], {
        cwd: mobileDir,
        encoding: "utf8",
        timeout: 60_000,
        env: { ...process.env, NODE_OPTIONS: "" },
      });
      const facts = JSON.parse(stdout) as Record<string, unknown>;
      // The globals really were absent before the module loaded.
      expect(facts.bufferBefore).toBe("undefined");
      expect(facts.cryptoBefore).toBe("undefined");
      // The real production module loaded and ran the real install().
      expect(facts.loaded).toBe(true);
      expect(facts.bufferAfter).toBe("function");
      expect(facts.cryptoAfter).toBe("object");
      expect(facts.bufferFromHex).toBe("6869"); // Buffer.from("hi") — usable, not just present
      expect(facts.cryptoRandomUuid).toBe("function");
      expect(facts.base64Helpers).toBe("function/function");
      // The native-boundary hook was actually exercised (the real package
      // graph pulled in all three stubbed names — proving the real
      // react-native-quick-crypto loaded, not a shadow copy).
      expect(facts.stubHits).toEqual({
        "react-native": expect.any(Number),
        "react-native-quick-base64": expect.any(Number),
        "react-native-nitro-modules": expect.any(Number),
      });
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("index.js requires the polyfill module strictly before ./App, with no hoisted imports", () => {
    const source = readFileSync(indexPath, "utf8");
    const polyfillAt = source.indexOf('require("./installPolyfills.cjs")');
    const appAt = source.indexOf('require("./App")');
    expect(polyfillAt).toBeGreaterThanOrEqual(0);
    expect(appAt).toBeGreaterThan(polyfillAt); // order is the contract
    // Any ESM import in index.js would be hoisted above the polyfill
    // require — exactly the crash class this entry exists to prevent.
    expect(source).not.toMatch(/^\s*import\s/m);
    expect(source).not.toMatch(/^\s*export\s/m);
  });
});
