/**
 * Source-scan pins for the HealthKit State-of-Mind bridge
 * (2026-09-22 independent-audit round 3, NEW-2 — audit E.1's residual:
 * react-native-health@1.19.0 links but carries NO State of Mind path, so
 * the mirror was permanently "too old" at runtime).
 *
 * The bridge itself is Objective-C compiled into the iOS app target —
 * a JS test runner cannot execute it (and this machine cannot run Xcode
 * at all), so these pins do what the repo's native hardening pins do:
 * assert the shipped FILES carry the exact surface the seam contract
 * (src/healthkit.ts "NATIVE-MODULE CONTRACT") requires, so an accidental
 * deletion or edit fails HERE — in CI — instead of silently reverting
 * the mirror to "unavailable" on devices. verify_native_release.mjs
 * enforces the same facts at the release-preflight level; these pins
 * run in the ordinary mobile suite.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = (...parts: string[]) => join(__dirname, "..", ...parts);

const BRIDGE_REL = "ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m";
const ENTITLEMENTS_REL = "ios/MindPattern/MindPattern.entitlements";
const PBXPROJ_REL = "ios/MindPattern.xcodeproj/project.pbxproj";

function read(rel: string): string {
  return readFileSync(root(rel), "utf8");
}

describe("HealthKit State-of-Mind native bridge (NEW-2)", () => {
  it("ships the bridge category inside the iOS app project", () => {
    expect(existsSync(root(BRIDGE_REL))).toBe(true);
  });

  it("exports exactly the three contract methods, promise-based", () => {
    const src = read(BRIDGE_REL);
    expect(src).toContain("RCT_EXPORT_METHOD(requestAuthorization");
    expect(src).toContain("RCT_EXPORT_METHOD(getAuthorizationStatus");
    expect(src).toContain("RCT_EXPORT_METHOD(saveStateOfMind");
    // Promise-based: the JS seam awaits these directly (the community
    // package's own callback-style methods would resolve undefined).
    expect(src).toMatch(/RCTPromiseResolveBlock/);
    expect(src).toMatch(/RCTPromiseRejectBlock/);
  });

  it("gates every HealthKit touch on iOS 18 and answers honestly below it", () => {
    const src = read(BRIDGE_REL);
    expect(src).toContain("@available(iOS 18.0, *)");
    // Pre-18 paths resolve/reject — never crash, never pretend success.
    expect(src).toMatch(/resolve\(@\(NO\)\)/);
    expect(src).toContain("E_UNAVAILABLE");
  });

  it("writes DailyMood samples via the pinned iOS 18 API surface", () => {
    const src = read(BRIDGE_REL);
    // API facts pinned against Apple's documentation JSON (see the file
    // header): class factory, daily-mood kind, share type, existing save.
    expect(src).toContain("stateOfMindWithDate:kind:valence:labels:associations:");
    expect(src).toContain("HKStateOfMindKindDailyMood");
    expect(src).toContain("[HKObjectType stateOfMindType]");
    expect(src).toContain("saveObject:withCompletion:");
  });

  it("keeps the write-only posture: read types are never requested", () => {
    const src = read(BRIDGE_REL);
    expect(src).toMatch(/readTypes:nil/);
    expect(src).not.toMatch(/readTypes:\[NSSet/);
  });

  it("validates the sample (kind label, valence bounds, calendar-day date)", () => {
    const src = read(BRIDGE_REL);
    expect(src).toContain("very_unpleasant");
    expect(src).toMatch(/valence < -2\.0 \|\| valence > 2\.0/);
    expect(src).toContain("en_US_POSIX");
    expect(src).toContain('dateFormat = @"yyyy-MM-dd"');
  });

  it("declares the HealthKit entitlement, write-only (no background delivery)", () => {
    const src = read(ENTITLEMENTS_REL);
    expect(src).toContain("com.apple.developer.healthkit");
    expect(src).toMatch(/<true\/>/);
    expect(src).not.toContain("healthkit.background-delivery");
  });

  it("compiles the bridge into the app target and signs the entitlements", () => {
    const pbx = read(PBXPROJ_REL);
    expect(pbx).toContain(
      "RCTAppleHealthKit+MindPatternStateOfMind.m in Sources */",
    );
    expect(pbx).toContain("MindPattern.entitlements */");
    // CODE_SIGN_ENTITLEMENTS in BOTH target configurations (Debug+Release).
    expect(pbx.match(/CODE_SIGN_ENTITLEMENTS = MindPattern\/MindPattern\.entitlements;/g)).toHaveLength(2);
  });

  it("keeps react-native-health declared (the category rides its module)", () => {
    const pkg = JSON.parse(read("package.json"));
    expect(typeof pkg.dependencies?.["react-native-health"]).toBe("string");
  });
});

describe("healthkit.ts capability gates on iOS 18 (NEW-2)", () => {
  // Stryker rewrites src/* in place during a mutation run (every literal
  // wrapped in a mutant ternary), so exact-text layout pins cannot hold
  // against the instrumented file. This pin guards the SHIPPED source, not
  // mutant behavior — it steps aside until the tree is restored.
  const src = read("src/healthkit.ts");
  it.skipIf(/stryMutAct_|__stryker__/.test(src))(
    "source pins the version check next to the module probe",
    () => {
      expect(src).toContain('Platform.OS === "ios"');
      expect(src).toMatch(/Platform\.Version/);
      expect(src).toMatch(/version < 18/);
    },
  );
});
