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
