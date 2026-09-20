/**
 * Fail-closed release preflight for the native projects and their
 * hardening surface.
 *
 * The JavaScript secure-store layer intentionally has no AsyncStorage key
 * fallback, and the HealthKit State of Mind mirror (src/healthkit.ts)
 * requires the two Health usage strings once ios/ exists. This repository
 * currently contains no generated native project, so do not let a JS-only
 * CI run be mistaken for a signed mobile artifact.
 *
 * Every check prints PASS/FAIL and the tool exits nonzero if ANY check
 * failed — including checks that could not run because the projects are
 * missing (unverifiable is failed, not green). Checks:
 *   1. ios/ and android/ native project directories exist.
 *   2. react-native-keychain is a direct dependency in package.json
 *      (src/secureStore.ts + src/biometricUnlock.ts depend on it; removal
 *      must fail preflight, not a device build).
 *   3. react-native-keychain is autolinked (npx react-native config).
 *   4. iOS Info.plist carries NSHealthShareUsageDescription +
 *      NSHealthUpdateUsageDescription — required whenever src/healthkit.ts
 *      is imported anywhere in the app source (the dependency is grepped,
 *      not assumed).
 *   5. Android's main manifest sets android:allowBackup="false".
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

let failed = 0;
let total = 0;

function pass(name, detail) {
  total += 1;
  console.log(`Native release preflight: PASS ${name}${detail ? ` — ${detail}` : ""}`);
}

function fail(name, detail) {
  total += 1;
  failed += 1;
  console.error(`Native release preflight: FAIL ${name} — ${detail}`);
}

// --- 1. The native projects themselves -----------------------------------
const iosExists = existsSync("ios");
const androidExists = existsSync("android");
const missing = [!iosExists && "ios", !androidExists && "android"].filter(Boolean);
if (missing.length === 0) {
  pass("native projects exist", "ios/ and android/ are present");
} else {
  fail(
    "native projects exist",
    `missing ${missing.join(" and ")} project${missing.length > 1 ? "s" : ""}. ` +
      "Generate/restore the native React Native projects, install pods, and validate Keychain/Keystore before releasing.",
  );
}

// --- 2. The keystore dependency is declared ------------------------------
// (Assertions like this one run from package.json alone, so they stay
//  verifiable even while the native projects are absent.)
let keychainDeclared = false;
try {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  keychainDeclared = typeof pkg?.dependencies?.["react-native-keychain"] === "string";
} catch {
  keychainDeclared = false;
}
if (keychainDeclared) {
  pass("react-native-keychain is a direct dependency", "the JS keychain seams stay backed by the package");
} else {
  fail(
    "react-native-keychain is a direct dependency",
    "src/secureStore.ts and src/biometricUnlock.ts hold session and wrap keys in the OS " +
      "Keychain/Keystore through it. Re-add react-native-keychain to package.json dependencies " +
      "before releasing — its removal must fail here, not on a device.",
  );
}

// --- 3. Autolinking --------------------------------------------------------
if (missing.length > 0) {
  fail(
    "react-native-keychain autolinking",
    "cannot inspect autolinking without the native projects (check 1 must pass first).",
  );
} else {
  const command = process.platform === "win32" ? "npx.cmd" : "npx";
  const config = spawnSync(command, ["react-native", "config"], { encoding: "utf8" });
  if (config.status !== 0) {
    fail("react-native-keychain autolinking", "`react-native config` could not inspect autolinking.");
  } else if (!config.stdout.includes("react-native-keychain")) {
    fail("react-native-keychain autolinking", "react-native-keychain is not autolinked.");
  } else {
    pass("react-native-keychain autolinking", "`react-native config` lists it");
  }
}

// --- 4. Health usage strings on iOS ---------------------------------------
/** Does the app source import the HealthKit seam? Grep, don't assume.
 *  Returns true, false, or null when the source tree could not be read
 *  (an unreadable tree fails toward "imported" — the strings are then
 *  demanded, never waived). */
function healthkitImported() {
  const importRe = /\bfrom\s+["'][^"']*healthkit["']/;
  const readableFiles = [];
  try {
    for (const entry of readdirSync("src", { withFileTypes: true, recursive: true })) {
      // parentPath already carries the starting directory.
      if (entry.isFile() && /\.(ts|tsx|js|jsx)$/.test(entry.name)) {
        readableFiles.push(join(entry.parentPath, entry.name));
      }
    }
  } catch {
    return null;
  }
  const sources = ["App.tsx", "index.js", ...readableFiles];
  return sources.some((file) => {
    try {
      return importRe.test(readFileSync(file, "utf8"));
    } catch {
      return false;
    }
  });
}

const healthUsed = healthkitImported() !== false;
if (!healthUsed) {
  pass("iOS Health usage strings", "src/healthkit.ts is not imported anywhere — no HealthKit surface to declare");
} else if (!iosExists) {
  fail(
    "iOS Health usage strings",
    "src/healthkit.ts is imported but ios/ is missing, so the Health usage strings cannot be verified. " +
      "When the project is generated, add NSHealthShareUsageDescription and NSHealthUpdateUsageDescription " +
      "to ios/<App>/Info.plist (see mobile/README.md for the wording guidance).",
  );
} else {
  const plists = [];
  try {
    for (const entry of readdirSync("ios", { withFileTypes: true, recursive: true })) {
      if (entry.isFile() && entry.name === "Info.plist") {
        plists.push(join(entry.parentPath, entry.name));
      }
    }
  } catch {
    /* handled by the empty-plists branch below */
  }
  const HEALTH_KEYS = ["NSHealthShareUsageDescription", "NSHealthUpdateUsageDescription"];
  const carrying = plists.filter((plist) => {
    try {
      const text = readFileSync(plist, "utf8");
      return HEALTH_KEYS.every((k) => text.includes(k));
    } catch {
      return false;
    }
  });
  if (carrying.length > 0) {
    pass("iOS Health usage strings", `both Health keys present in ${carrying[0]}`);
  } else if (plists.length === 0) {
    fail("iOS Health usage strings", "no Info.plist found under ios/ — cannot verify the Health usage strings.");
  } else {
    fail(
      "iOS Health usage strings",
      `src/healthkit.ts is imported, so Info.plist needs BOTH ${HEALTH_KEYS.join(" and ")} ` +
        "(MindPattern writes State of Mind samples; iOS refuses the app outright without the strings).",
    );
  }
}

// --- 5. Android: no platform backups of app data --------------------------
const MANIFEST_PATH = join("android", "app", "src", "main", "AndroidManifest.xml");
if (!androidExists) {
  fail(
    "Android allowBackup",
    "android/ is missing, so the manifest cannot be verified (check 1 must pass first).",
  );
} else if (!existsSync(MANIFEST_PATH)) {
  fail("Android allowBackup", `no AndroidManifest.xml at ${MANIFEST_PATH}.`);
} else if (readFileSync(MANIFEST_PATH, "utf8").includes('android:allowBackup="false"')) {
  pass("Android allowBackup", 'android:allowBackup="false" is set on <application>');
} else {
  fail(
    "Android allowBackup",
    'the <application> element must set android:allowBackup="false" — ciphertext in a forensic backup is ' +
      "harmless, but preferences and metadata (reminder times, mirror opt-ins, queued entry ids) must not ride " +
      "along into platform backups.",
  );
}

// --- verdict ---------------------------------------------------------------
if (failed > 0) {
  console.error(`Native release preflight failed: ${failed} of ${total} checks did not pass.`);
  process.exit(1);
}
console.log(`Native release preflight passed: all ${total} checks green.`);
