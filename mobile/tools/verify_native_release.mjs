/**
 * Fail-closed release preflight for the OS-keystore dependency.
 *
 * The JavaScript secure-store layer intentionally has no AsyncStorage key
 * fallback. A release therefore needs real iOS/Android projects and React
 * Native autolinking for react-native-keychain. This repository currently
 * contains neither generated native project, so do not let a JS-only CI run
 * be mistaken for a signed mobile artifact.
 */
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";

const requiredProjects = ["ios", "android"];
const missing = requiredProjects.filter((directory) => !existsSync(directory));
if (missing.length > 0) {
  console.error(
    `Native release preflight failed: missing ${missing.join(" and ")} project${missing.length > 1 ? "s" : ""}. ` +
      "Generate/restore the native React Native projects, install pods, and validate Keychain/Keystore before releasing.",
  );
  process.exit(1);
}

const command = process.platform === "win32" ? "npx.cmd" : "npx";
const config = spawnSync(command, ["react-native", "config"], { encoding: "utf8" });
if (config.status !== 0) {
  console.error("Native release preflight failed: `react-native config` could not inspect autolinking.");
  process.exit(config.status ?? 1);
}
if (!config.stdout.includes("react-native-keychain")) {
  console.error("Native release preflight failed: react-native-keychain is not autolinked.");
  process.exit(1);
}

console.log("Native release preflight passed: projects exist and react-native-keychain is autolinked.");
