import { expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

it("the iOS release wrapper runs its real preflight from the mobile root and preserves Xcode's working directory", () => {
  const mobile = fileURLToPath(new URL("../", import.meta.url)), ios = join(mobile, "ios");
  const native = mkdtempSync(join(tmpdir(), "mindpattern-xcode-wrapper-"));
  try {
    mkdirSync(join(native, "scripts"));
    writeFileSync(join(native, "scripts", "react-native-xcode.sh"), '#!/bin/sh\nset -eu\nprintf "Xcode bundle working directory: %s\\n" "$PWD"\n', { mode: 0o755 });
    const output = execFileSync("sh", [join(mobile, "tools", "bundle_ios.sh")], {
      cwd: ios, encoding: "utf8", timeout: 30_000,
      env: { ...process.env, CONFIGURATION: "Release", PROJECT_DIR: ios, NODE_BINARY: process.execPath,
        REACT_NATIVE_PATH: native, MINDPATTERN_API_ORIGIN: "https://synthetic-release-origin.mindpattern-audit.com" },
    });
    expect(output).toContain("Native release preflight passed: all 22 checks green.");
    expect(output).toContain(`Xcode bundle working directory: ${ios}`);
  } finally { rmSync(native, { recursive: true, force: true }); }
});
