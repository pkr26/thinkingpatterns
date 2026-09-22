/**
 * Fail-closed release preflight for the native projects and their
 * hardening surface.
 *
 * The JavaScript secure-store layer intentionally has no AsyncStorage key
 * fallback, and the HealthKit State of Mind mirror (src/healthkit.ts)
 * requires the two Health usage strings once ios/ exists. The ios/ and
 * android/ projects are committed (2026-09-21 audit E-1); this preflight
 * keeps a JS-only CI run from being mistaken for a signed, hardened
 * mobile artifact.
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
 *   6. Android: FLAG_SECURE in MainActivity + windowSoftInputMode
 *      "adjustResize" on the activity (2026-09-22 round 3: the 2026-09-21
 *      E-1 hardening shipped these; preflight must notice a regression).
 *   7. iOS: the HealthKit entitlement file exists, carries
 *      com.apple.developer.healthkit, and BOTH target configurations sign
 *      it (CODE_SIGN_ENTITLEMENTS).
 *   8. iOS: the State-of-Mind bridge
 *      (MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m)
 *      is referenced by the project, exports the three seam-contract
 *      methods promise-based, gates them on @available(iOS 18.0, *), and
 *      keeps the write-only posture (readTypes:nil) — 2026-09-22 round 3,
 *      NEW-2: react-native-health@1.19.0 has no State of Mind path, so
 *      this category IS the HealthKit mirror.
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

// --- 6. Android hardening: FLAG_SECURE + adjustResize (round 3) -------------
if (!androidExists) {
  fail("Android FLAG_SECURE/adjustResize", "android/ is missing (check 1 must pass first).");
} else {
  const mainActivityPath = join("android", "app", "src", "main", "java", "com", "mindpattern", "MainActivity.kt");
  let flagSecure = false;
  try {
    flagSecure = readFileSync(mainActivityPath, "utf8").includes("FLAG_SECURE");
  } catch {
    /* missing file -> flagSecure stays false */
  }
  if (flagSecure) {
    pass("Android FLAG_SECURE", "MainActivity sets FLAG_SECURE (no app-switcher snapshots)");
  } else {
    fail(
      "Android FLAG_SECURE",
      `MainActivity.kt (${mainActivityPath}) must set WindowManager.LayoutParams.FLAG_SECURE in onCreate — ` +
        "decrypted journal content must not appear in the recents/app-switcher thumbnail.",
    );
  }

  let adjustResize = false;
  try {
    adjustResize = readFileSync(MANIFEST_PATH, "utf8").includes('android:windowSoftInputMode="adjustResize"');
  } catch {
    /* manifest already failed check 5 if missing */
  }
  if (adjustResize) {
    pass("Android adjustResize", 'activity sets android:windowSoftInputMode="adjustResize"');
  } else {
    fail(
      "Android adjustResize",
      'the main activity must set android:windowSoftInputMode="adjustResize" — anything else lets the ' +
        "keyboard overlay the entry composer and the crisis-banner safe areas.",
    );
  }
}

// --- 7. iOS HealthKit entitlement (round 3, NEW-2) ----------------------------
const ENTITLEMENTS_PATH = join("ios", "MindPattern", "MindPattern.entitlements");
if (!iosExists) {
  fail("iOS HealthKit entitlement", "ios/ is missing (check 1 must pass first).");
} else if (!existsSync(ENTITLEMENTS_PATH)) {
  fail(
    "iOS HealthKit entitlement",
    `${ENTITLEMENTS_PATH} is missing — without com.apple.developer.healthkit every HealthKit call fails at ` +
      "runtime and the State-of-Mind mirror reads as unavailable on every device.",
  );
} else {
  const entitlements = readFileSync(ENTITLEMENTS_PATH, "utf8");
  const hasHealthkit = entitlements.includes("com.apple.developer.healthkit");
  let signedTwice = false;
  try {
    const pbx = readFileSync(join("ios", "MindPattern.xcodeproj", "project.pbxproj"), "utf8");
    signedTwice =
      (pbx.match(/CODE_SIGN_ENTITLEMENTS = MindPattern\/MindPattern\.entitlements;/g) ?? []).length === 2;
  } catch {
    signedTwice = false;
  }
  if (hasHealthkit && signedTwice) {
    pass("iOS HealthKit entitlement", "declared and signed by both target configurations");
  } else {
    fail(
      "iOS HealthKit entitlement",
      `${hasHealthkit ? "entitlement key present" : "com.apple.developer.healthkit missing"}; ` +
        `${signedTwice ? "CODE_SIGN_ENTITLEMENTS set" : "CODE_SIGN_ENTITLEMENTS missing from a target configuration"} ` +
        "(needs it in BOTH Debug and Release).",
    );
  }
}

// --- 8. iOS State-of-Mind bridge (round 3, NEW-2) ------------------------------
const BRIDGE_PATH = join("ios", "MindPattern", "HealthBridge", "RCTAppleHealthKit+MindPatternStateOfMind.m");
if (!iosExists) {
  fail("iOS State-of-Mind bridge", "ios/ is missing (check 1 must pass first).");
} else if (!existsSync(BRIDGE_PATH)) {
  fail(
    "iOS State-of-Mind bridge",
    `${BRIDGE_PATH} is missing — react-native-health@1.19.0 has NO State of Mind path, so without this ` +
      "category the HealthKit mirror (src/healthkit.ts) is permanently unavailable (audit NEW-2).",
  );
} else {
  const bridge = readFileSync(BRIDGE_PATH, "utf8");
  const required = [
    "RCT_EXPORT_METHOD(requestAuthorization",
    "RCT_EXPORT_METHOD(getAuthorizationStatus",
    "RCT_EXPORT_METHOD(saveStateOfMind",
    "RCTPromiseResolveBlock",
    "@available(iOS 18.0, *)",
    "stateOfMindWithDate:kind:valence:labels:associations:",
    "HKStateOfMindKindDailyMood",
    "[HKObjectType stateOfMindType]",
    "saveObject:withCompletion:",
    "readTypes:nil",
  ];
  const missingBits = required.filter((needle) => !bridge.includes(needle));
  let inSources = false;
  try {
    const pbx = readFileSync(join("ios", "MindPattern.xcodeproj", "project.pbxproj"), "utf8");
    inSources = pbx.includes("RCTAppleHealthKit+MindPatternStateOfMind.m in Sources */");
  } catch {
    inSources = false;
  }
  if (missingBits.length === 0 && inSources) {
    pass("iOS State-of-Mind bridge", "all three contract methods present, iOS-18-gated, write-only, compiled in");
  } else {
    fail(
      "iOS State-of-Mind bridge",
      `${missingBits.length > 0 ? `missing from the bridge: ${missingBits.join(", ")}` : "bridge present"}; ` +
        `${inSources ? "referenced by the Xcode project" : "NOT in the app target's Sources phase — it will not compile in"}.`,
    );
  }
}

// --- verdict ---------------------------------------------------------------
if (failed > 0) {
  console.error(`Native release preflight failed: ${failed} of ${total} checks did not pass.`);
  process.exit(1);
}
console.log(`Native release preflight passed: all ${total} checks green.`);
