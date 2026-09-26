# R8 rules for release builds (audit F-1, 2026-09-26: minifyEnabled is on).
#
# Shrinking runs WITH optimization but WITHOUT obfuscation: the Hermes JS
# bundle already carries the app logic, so renaming Java/Kotlin symbols
# buys almost nothing while risking reflective bridge lookups and making
# crash triage harder. react-native, react-native-keychain, notifee and
# react-native-health ship their own consumer rules; the keeps below are
# the belt-and-braces set on top of those.

-dontobfuscate

# The React bridge resolves native modules and view managers by name.
-keep class com.facebook.react.** { *; }
-keep interface com.facebook.react.** { *; }
-dontwarn com.facebook.react.**

# App package: MainActivity/MainApplication are referenced from the merged
# manifest; the HealthKit-equivalent native modules are looked up by the
# JS bridge.
-keep class com.mindpattern.** { *; }

# Autolinked native modules the bridge talks to by registered name.
# (react-native-health is iOS-only — no Android classes to keep.)
-keep class io.invertase.notifee.** { *; }
-keep class com.oblador.keychain.** { *; }
