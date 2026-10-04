# Fathom Mobile

React Native client for encrypted journaling, reflection, and optional therapist
sharing. Native iOS and Android projects are committed alongside the TypeScript
application. The native target and storage namespace retain the internal name
`MindPattern`; the user-facing product name is Fathom.

## Development

Run these commands from `mobile/`:

```bash
npm ci
npm run typecheck
npm test
npm run verify:vectors
npm run verify:dependency-patches
npm run verify:native-release
```

`npm ci` applies the reviewed dependency patches in
[tools/dependency-patches](tools/dependency-patches/README.md). Keep their manifest,
verification tools, and upstream licenses together. `npm test` runs the behavioral
suite with coverage; `npm run test:mutation` runs the mutation checks separately.
Typechecking rejects unused locals and parameters as well as type errors.

For iOS, install the Ruby and CocoaPods dependencies before the first native build:

```bash
cd ios
bundle install
bundle exec pod install
cd ..
npm run ios
```

`ios/Gemfile.lock` and `ios/Podfile.lock` are committed. Pods and build outputs are
local artifacts. Android development uses `npm run android`; start Metro
separately with `npm start` when needed. Use the toolchain versions declared in
`package.json`, the native projects, and their lockfiles.

## API configuration

Debug builds default to `http://localhost:8000`. Release builds require a real
HTTPS `MINDPATTERN_API_ORIGIN`, captured by the Babel/native build configuration.
Missing, example, and insecure production origins fail closed. The login screen
shows the selected server and allows changing it before authentication.

Requests use `/api/v1`. Plain HTTP is permitted only for device-local loopback
hosts; credentials and data keys must never be sent to a LAN or public cleartext
origin. Server changes retire the previous origin's local account state.

## Code layout

| Location | Responsibility |
| --- | --- |
| `App.tsx`, `src/navigation.tsx` | Providers, privacy overlay, and authenticated navigation. |
| `src/screens/`, `src/components/` | Screens and shared accessible controls. |
| `src/api/client.ts` | Transport, session credentials, API contracts, and origin changes. |
| `src/crypto/` | Key derivation, envelopes, journal/audio payloads, sharing, and recovery. |
| `src/vault.ts`, `src/secureStore.ts` | In-memory account keys and encrypted device storage. |
| `src/accountStorage.ts`, `src/accountErasure.ts` | Account storage inventory and retryable erasure. |
| `src/localRekey.ts`, `src/localWriteGuard.ts` | Key rotation and account-scoped write ownership. |
| `src/offlineQueue.ts`, `src/audioQueue.ts` | Encrypted uploads, acknowledgments, and recovery. |
| `src/journalDraft.ts` | Encrypted draft persistence and revision checks. |
| `src/audio/` | Recording, playback, and plaintext scratch-file cleanup. |
| `src/brain/` | On-device sentiment and statistics; [remaining port work](src/brain/PORT.md). |
| `src/locales/`, `src/strings.ts`, `src/theme.tsx` | Localized copy and shared design tokens. |
| `tests/`, `tools/` | Regression coverage, vector verification, and release tooling. |
| `ios/`, `android/` | Native targets and platform privacy controls. |

## Data and consent contracts

- **Encryption:** entries are encrypted before upload using AES-256-GCM with
  `nonce(12) || ciphertext || tag(16)`. AAD binds context, account, item, and the
  applicable content version. Authentication uses the fixed PBKDF2/HKDF contract;
  v2 accounts wrap a random data key with a password-derived key.
- **Key lifetime:** the unlocked account keys live in `vault.ts` and are zeroized
  on lock/sign-out. Opt-in biometric unlock stores a separately protected data-key
  wrap. Session values use a per-install Keychain/Keystore key; unavailable native
  key storage fails closed, with no plaintext key fallback.
- **Processing:** personalized analysis can temporarily send the data key to a
  single-use, memory-only server session. This requires an explicit user action
  and consent. Generic questions and local sentiment scoring need no such session.
- **Voice:** recording uses `expo-audio`. Transcription requires the separate
  voice consent; users can optionally retain an encrypted recording. Plaintext
  recording/playback files are scrubbed after use and during cold start, account
  erasure, and server retirement.
- **Local support:** crisis-language matching runs before encryption using the
  shared phrase contract. Crisis resources work offline; the personal safety plan
  is encrypted locally and requires an unlocked vault.
- **Exports:** full-account export is disabled until a native streaming-to-file
  implementation is available. Saved recordings have a separate export action.

[shared/vectors.json](../shared/vectors.json) and
[shared/audio_vectors.json](../shared/audio_vectors.json) pin the crypto formats.
Run the vector verifier and regression suite whenever changing crypto code.
The native crypto entry has no Node fallback; tests use a Node adapter for the
same module interfaces. [Bootstrap tests](tests/bootstrap.test.ts) verify that
Buffer and crypto globals are installed before the application loads.

## Synchronization and local ownership

Mobile and web share the server's compare-and-swap contract. Editing sends the
next content version; a `409 version_conflict` fetches and decrypts the current
server entry so the user can choose which version to keep. A second conflict is
surfaced rather than retried indefinitely. A remotely deleted entry remains a
visible save failure. There is no automatic text merge.

Entry-version and analysis-generation guards reject known rollbacks.
Device-local high-water marks are encrypted, with in-memory mirrors for the
current process. Offline entry and audio queues retain recoverable rejected
uploads. Account, origin, and key-generation checks prevent stale asynchronous
work from writing into a different session.

## Native release checks

`npm run verify:native-release` checks project wiring, linked dependencies,
HealthKit permissions and bridge methods, Android backup/network/signing rules,
release minification, iOS snapshot shielding, and tracked-keystore hygiene.
The tool fails when a required check cannot run. Its regression coverage lives in
[tests/nativeBuildTools.test.ts](tests/nativeBuildTools.test.ts).

Keep these platform contracts intact when updating generated project files:

- Android disables backups, sets `FLAG_SECURE`, and uses `adjustResize`.
  Release network configuration trusts system CAs and limits cleartext to
  loopback. Debug builds additionally support user CAs for local development.
- Android release signing reads private `android/keystore.properties`; use
  [the example](android/keystore.properties.example). Missing release credentials
  fail the build. Release keys and passwords must remain outside version control.
- iOS uses native snapshot and recording shields in
  [AppDelegate.swift](ios/MindPattern/AppDelegate.swift), with the JavaScript
  overlay as an additional layer. Device-only Keychain accessibility must remain
  in place for session keys and biometric wraps.
- Notification permission is requested when the user enables a reminder,
  never on application startup. Stable daily/check-in IDs avoid duplicate
  schedules after restarts.
- HealthKit is an opt-in, write-only mirror of explicit mood check-ins.
  Text-derived estimates are never mirrored. The committed
  [State of Mind bridge](ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m)
  extends the linked `react-native-health` module and requires iOS 18 or later.
  Both target configurations sign the HealthKit entitlement. Preserve the
  `NSHealthUpdateUsageDescription` and `NSHealthShareUsageDescription` strings in
  [Info.plist](ios/MindPattern/Info.plist); they must explain write-only mood
  sharing and that Fathom does not read Health data.

Static checks do not prove native behavior. Run the
[device verification checklist](tools/DEVICE_VERIFICATION_CHECKLIST.md) for each
release candidate on both platforms and retain the results with release evidence.
It covers biometric invalidation, reinstall behavior, notifications, privacy
shields, offline persistence, and other hardware-dependent behavior.

TLS/SPKI pinning is not implemented. Transport limitations and the remaining
backup/privacy work are recorded in the repository's
[security residuals](../docs/SECURITY_RESIDUALS.md).
