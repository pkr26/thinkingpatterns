# Dependency security backports and native compatibility

`npm ci` runs `tools/apply_dependency_patches.mjs`. The checked-in manifest
requires the exact installed versions and SHA-256 of every original and
replacement source file. Unknown source, damaged artifacts, or a version
change fail installation until reviewed. Re-running is idempotent.

These are proposed upstream fixes, **not published or merged releases**:

- `braces@3.0.3`: [upstream PR 72](https://github.com/micromatch/braces/pull/72),
  commits from `d0d575e55e74a4e0218e5248fafb79efc3e54ebb` through `28d440b5dd449dbf1fe6f3506cf94ecca4d02660`, applies the parser and all recursive AST walkers' nesting
  cap of 100. Includes parentheses and direct AST inputs. Original MIT
  license is retained next to the source.
- `node-forge@1.4.0`: [upstream PR 1152, commit ceba344](https://github.com/digitalbazaar/forge/pull/1152/commits/ceba34402e329f0365134f23fe19898756527d65),
  requires the nested DigestAlgorithm sequence to contain exactly an OID
  plus an optional NULL. It uses the existing ASN.1 validator and changes
  no signature algorithms. Original BSD/GPL licensing is retained.

Run `npm run verify:dependency-patches` after installation. It exercises
deeply nested patterns, direct ASTs, normal globs, normal RSA signatures,
optional-NULL DigestAlgorithm inputs, and deliberately signed malformed
DigestAlgorithm structures that the unpatched verifier accepts.

The npm registry currently reports no patched releases for
[braces GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
and [forge GHSA-86w9-cpqp-85rv](https://github.com/advisories/GHSA-86w9-cpqp-85rv).
**Package versions stay unchanged; raw `npm audit` remains red.** This is a
tested local mitigation, not suppression or a claim that registry advisories
are gone. CI/release runs `npm run audit:dependencies`: it first verifies the
exact patched bytes and attack regressions, then parses the registry report
and permits only these two advisory URLs. Any unrelated advisory or audit
service failure remains a hard failure. Remove the allowlist and backports
only after reviewing fixed upstream releases and re-running all checks.

Reachability: braces handles trusted project/tooling glob inputs through
Metro/React Native CLI; forge is Expo CLI certificate/code-signing tooling.
Neither implements the application's runtime encryption, which uses the
native quick-crypto engine. Tooling signature verification still requires
the strict fix and is covered by the malformed-structure regression.

The same exact-version/source-hash mechanism patches the Gradle plugin
compiler declaration in `expo-modules-autolinking@57.0.13` and
`expo-modules-core@57.0.20` from Kotlin 2.1.20 to 2.2.21. This matches
[Expo's current plugin sources](https://github.com/expo/expo/blob/main/packages/expo-modules-autolinking/android/expo-gradle-plugin/build.gradle.kts)
and addresses the [reported compiler metadata incompatibility](https://github.com/expo/expo/issues/49550).
Gradle 9.4.1 is retained because the installed AGP 9.2.1 requires it;
the app's Kotlin compiler is also pinned to 2.2.21. A fresh `npm ci`
must apply these declarations before native compilation. Cached compiled
plugins are insufficient evidence; the final Android check recompiles the
included plugins. The Expo core compatibility patch also omits the removed
AGP 9 library `targetSdk` setter (the app retains target SDK 36), and
includes React Native's `ReactCommon` headers for its 0.87 ErrorUtils
forwarder. The root Gradle configuration explicitly enables BuildConfig
for Expo LogBox, which declares a custom field. These changes are exercised
by native compilation and do not replace the application's privacy gates.

The iOS backport in `expo-modules-autolinking@57.0.13` preserves earlier
React Native post-install xcconfig edits when adding Expo macro flags. It
backports [Expo commit 1ae6855](https://github.com/expo/expo/commit/1ae6855e399930d57322c84cc73f76c36a8a3e62)
by reading an existing xcconfig from disk instead of reconstructing it from
stale CocoaPods settings. Package versions, module checking and warning
policies stay unchanged. The existing exact-hash installer and verifier cover
the additional source artifact.

With the iOS Gemfile dependencies installed, run
`npm run verify:dependency-patches:ios`. Its real Xcodeproj regression checks
that C, C++, Swift and header-search edits survive, repeated calls are
idempotent, an existing macro preserves every byte, and a missing file uses
the existing settings. The regression requires Ruby/CocoaPods, but no Xcode
SDK, simulator, native compilation or test application.

Expo 57.0.26 also receives the exact React Native 0.87 factory backport from https://github.com/expo/expo/commit/2ca97ce502a01b188c76dd1a4258d8dbd19fbb0e. It removes obsolete bridge configuration calls and keeps bundle configuration, runtime delegation, and root-view customization. The existing exact-source loader verifies this file on install and refuses unknown source bytes. React Native and Expo versions, podspecs, module warning flags, and package locks stay unchanged. A real app-host SDK build remains required; loader checks do not establish native compilation or runtime behavior.

For the locked react-native-health 1.19.0 / React Native 0.87.1 pair, preserve React Native's injected `callableJSModules` when dispatching HealthKit events. Remove the obsolete manual bridge assignment and its unreferenced private singleton helper; retain listener gating and public event name/body dispatch. This is an adaptation to the primary RN 0.87 interfaces, not a claimed upstream HealthKit fix. The generic loader refuses unknown source and leaves all package versions unchanged. The old source failed the real SDK compile on `setBridge:`. Positive app-host event-wiring and native mutation qualification remain separate required runtime checks.
