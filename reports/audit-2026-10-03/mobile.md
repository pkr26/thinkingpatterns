# Mobile audit — Fathom / MindPattern

Audit date: 2026-10-03. Scope: the tracked `mobile/` tree, native iOS/Android integration, local storage/queues/state/cryptography and mobile tests. No tracked application code was changed. This is an audit of the present source, not a repetition of historical audit conclusions.

## Decision and score

**Do not ship the current mobile release. Advisory mobile score: 50/100.** There is substantial thoughtful work here—authenticated encryption, local vault locking, opaque offline queues, bounded inputs, origin pinning, cautious crisis copy, explicit sharing consent, useful questionnaire support and a large passing test suite. However, both native launchers request a JS component that is never registered, the added iOS Health bridge has a compiler defect, actual questionnaire touch events fail, recovery reset supplies the wrong token shape, and ordinary queue races can delete retained recordings. These defects invalidate a high production-readiness score despite green mocked tests.

The score is a reviewer judgment, not a scientific measurement. Mobile architecture and test investment are much stronger than native release readiness. This score should be integrated with the separate backend/web/infrastructure review rather than presented as the entire app's score.

## Coverage and limits

All **248 tracked mobile files** were byte-read, inventoried and classified with sizes/hashes and appropriate structural review. The detailed manifest is `file-coverage.json`, also available as `file-coverage.json`.

| Review type | Files |
|---|---:|
| Full manual original-source/text/configuration read | 81 |
| Complete executable/type/configuration read; comments structurally scanned | 43 |
| Test/helper AST, assertion/import scan and suite use | 105 |
| Structured documentation plus targeted prose review | 3 |
| Binary metadata inventory | 12 |
| Generated lexicon/localization structural review | 3 |
| Structured lockfile review | 1 |
| Total | 248 |

**Every production executable statement, type declaration and configuration value was read.** The followup completed all formerly selective/structural-only production source, including the full 1,776-line API client and large Settings/History/Insights screens. Faithful TypeScript printer projections with comments removed preserved all code/types/JSX/string literals; original source plus remaining-gap reads were used where already partially read. Comments, test assertions, documentation prose, generated lexicon/catalog words and binary artifacts retain explicitly recorded structural/targeted review rather than an every-word manual claim. Generated linguistic contents were not independently clinically validated. PNG assets were inventoried for dimensions/hashes, not reviewed as artwork. Installed dependency native code was inspected separately as evidence and is not miscounted as tracked source.

No native app was successfully built or booted, and no device UI screenshots were inspected in this mobile sub-audit. Native hardware behavior, notification delivery, platform crypto interop, real VoiceOver/TalkBack navigation, large-font rendering, reinstall semantics and real HealthKit writes remain unverified. Device expectations below are identified as static/native-contract findings or explicit evidence gaps.

## Validation performed

| Command / check | Result | Evidence |
|---|---|---|
| `npm run typecheck` | Pass | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-typecheck.log` |
| `npm test` | 96 passed files, 1 skipped; 2,099 passed tests, 1 skipped | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-test.log` |
| Coverage | Statements 91.5%; branches 86.1%; functions 85%; lines 94% | Same log |
| `npm run verify:native-release` | Pass, all 14 static checks | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-native.log` |
| `npm run verify:vectors` | Pass: 4 decrypt vectors, 6 encrypt vectors, 3 wrap vectors, 16 AAD cases, 4 envelope vectors | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-vectors.log` |
| `npx vitest run --config redteam.vitest.config.ts` | 97 passed files, 1 skipped; 2,107 passed tests, 1 skipped | `/tmp/mindpattern-mobile-redteam.log` |
| Five temporary bug-reproduction tests | All reproduced the current bad behavior | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-regressions.log`; `/tmp/mobile-audit-regression.test.ts` |
| Android `./gradlew :app:assembleDebug --offline` | Blocked: Android SDK location missing | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-android-build.log` |
| `xcodebuild -version` | Blocked: active developer directory is CommandLineTools rather than full Xcode | Toolchain check; no iOS build attempted |
| Isolated Objective-C category compilation | Compiler rejects category on a forward-declared class | `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/objc-category-proof.log` |

The temporary reproduction tests assert the faulty current behavior; their passing is **evidence of defects**, not evidence that the app is fixed. They live outside the repository. Red-team configuration merges its includes with the base suite, so its 2,107 count includes the ordinary suite; it adds eight cases rather than 2,107 independent attack cases. Mutation testing was not run.

The coverage run logs a parse failure when `coverage.include: ["src/**"]` attempts to transform `src/brain/PORT.md`; Vitest skips that file and exits successfully. Narrow this to source extensions and exclude generated/data files explicitly. Passing coverage gates do not establish native correctness: the native preflight passes even though the component registration and Objective-C source contracts below are broken.

The root auditor independently ran current `npm audit`; the mobile lock produced 30 affected packages (29 high, 1 moderate), primarily propagated build/tool dependencies. Those are dependency remediation work, not proof of 29 exploitable shipped mobile runtime flaws. The JSON is `/Users/pradeepreddy/Desktop/mental_health_application/reports/audit-2026-10-03/validation-logs/mobile-npm-audit.json`.

## Confirmed high-priority defects

### M01 — HIGH, both native launchers request an unregistered component

**Evidence:** `mobile/index.js:23` registers `"Fathom"`; `mobile/android/app/src/main/java/com/mindpattern/MainActivity.kt:16` returns `"MindPattern"`; `mobile/ios/MindPattern/AppDelegate.swift:45` starts `"MindPattern"`.

React Native native startup asks for a named JS root. The bundle registers a different name, so Android and iOS cannot enter the application. Branding can be Fathom while the internal registered name remains MindPattern; the names simply must agree. This is a release-blocking functional defect, not a critical security vulnerability. Static name mismatch is conclusive; no device run was possible here.

**Reproduce:** launch either platform with this bundle and launcher configuration; the requested root `MindPattern` is absent from `AppRegistry`. **Fix:** centralize the root name and verify the JS registry, Android launcher and iOS factory use it. Add a contract test comparing all three and an actual cold-boot release smoke test.

### M02 — HIGH, iOS Health category does not have a class interface

**Evidence:** `mobile/ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m:48` only forward-declares `RCTAppleHealthKit`, then declares a category at `:50`. The file is included in the app project's source build phase. Its comment asserts the forward declaration is sufficient; Objective-C requires the complete class interface to declare/implement the category.

A minimal compiler proof returns `cannot define category for undefined class` and `cannot find interface declaration`. A full iOS build could not run, but this language error is independent of hardware. **Fix:** import the pod's public `RCTAppleHealthKit.h` through a supported header/module path, and compile the target with warnings treated appropriately. Static regex detection of three exported methods is inadequate.

### M03 — HIGH, HealthKit factory and valence contracts are wrong

**Evidence:** the same native bridge `:208–212` calls `stateOfMindWithDate:kind:valence:labels:associations:` without the final `metadata:` selector component. Apple's documented factory includes that component. Once the category compilation is repaired, the current selector is not the documented factory and can fail with an unrecognized selector. The JS seam at `mobile/src/healthkit.ts:238` sends `KINDS.indexOf(kind) - 2`, producing `-2,-1,0,1,2`; the native validator at `.m:174–175` accepts `[-2,2]`.

Apple State of Mind uses continuous valence from negative one to positive one. Extremes `±2` are invalid, and quantized `±1` overwrites the meaning of intermediate app moods. **Fix:** pass the bounded continuous input valence, retain classification only as local/UI context, use the complete `metadata:nil` factory call and perform real iOS 18+ Health writes for each boundary and intermediate value.

Primary documentation: [Apple HKStateOfMind Objective-C factory](https://developer.apple.com/documentation/healthkit/hkstateofmind/stateofmindwithdate%3Akind%3Avalence%3Alabels%3Aassociations%3Ametadata%3A?language=objc); [Apple WWDC 2024 State of Mind session](https://developer.apple.com/videos/play/wwdc2024/10109/). Official factory JSON was saved to `/tmp/mindpattern-apple-hk-factory.json`.

### M04 — HIGH, a real Record questionnaire tap is treated as a retry record

**Evidence:** `mobile/src/screens/MeasuresScreen.tsx:191` defines `submit(retryOf?: PendingMeasure)`; `:493` passes it directly as `onPress={submit}`. `mobile/src/components/buttons.tsx:37` forwards that function directly to React Native `TouchableOpacity`. Native `onPress` supplies a `GestureResponderEvent`, which is truthy and is therefore used at `MeasuresScreen:193–199` as a `PendingMeasure`.

After the user completes PHQ-9/GAD-7 and taps Record, `record.kind`, `record.picks` and other record fields are absent; payload/safety evaluation fails and `createMeasure` never runs. Current test helpers invoke `onPress()` with no event (`mobile/tests/helpers/rtr.tsx:64`) and hide this defect.

**Reproduced:** rendered the real MeasuresScreen, completed all nine answers, invoked the real Record handler with a native-shaped event; the app showed “Not recorded” and the API call was absent. **Fix:** `onPress={() => void submit()}`, use a separate retry function, and make press helpers pass native-shaped event arguments.

### M05 — HIGH, password recovery passes a response object as a token

**Evidence:** `mobile/src/recoveryFlow.ts:83` assigns `await api.openProcessingSession(...)` to `processingToken` without extracting `session_token`, and passes it at `:103`. `mobile/src/api/client.ts:1184` expects a string; `:1190` places it in `X-Processing-Token`. `openProcessingSession` at `:1546–1554` returns the JSON response. Other real callers extract `.session_token`, including `mobile/src/rotation.ts:273,508–509`.

A real processing-session response is an object; a Fetch header becomes `[object Object]` and the server cannot validate the reset token. Typecheck misses this because the generic request boundary returns `any`. The dedicated recovery-flow test at `mobile/tests/recoveryFlow.test.ts:13` incorrectly returns the bare string `"pst-1"`; the shared API mock correctly returns an object.

**Fix:** destructure a validated processing-session response and type every API result at the boundary. Exercise recovery through the real client request layer using the real response schema, including a network failure after server commit and recovery retry.

### M06 — HIGH, normal reconnect can delete the only retained voice recording

**Evidence:** `mobile/src/store.tsx:213–214` starts text-queue and audio-queue flushes concurrently. Offline voice entry creation queues the primary audit text entry and its retained audio separately. `mobile/src/audioQueue.ts:182–186` treats parent-not-found `404` as permanent and removes the audio row.

If the audio upload reaches the server before the queued parent creation finishes, the server returns 404 and the only queued recording is removed. Origin pinning does not solve this same-origin dependency race. A temporary regression confirms an upload returning 404 deletes the audio queue row.

**Fix:** model parent-entry acknowledgment explicitly; only upload its attachment after parent creation succeeds. Retain a 404 while the primary audit is pending or rejected, and distinguish an authoritative permanent deletion from temporary absence. Test slow parent creation / fast attachment request, retries, network ambiguity, deletion and consent withdrawal.

### M07 — HIGH, late audio flush can delete a newer take or resurrect erased rows

**Evidence:** `mobile/src/audioQueue.ts:78–114` serializes enqueue/replacement, but `flushAudioQueue:144–192` does not participate in that mutex or use a single-flight/idempotent generation contract. It reads one row, awaits upload, then unconditionally removes the storage key at `:172`. Replacing the same entry's take while that upload is pending means the late old success deletes the newer row. A temporary regression confirms the new replacement disappears.

The generation fence is checked only at loop entry `:152`. After `clearAudioQueue` increments the generation and removes rows, an earlier upload returning 401 can write the old row back at `:179`. Thus the comment at `:54–55` promising clear wins every in-flight stash/flush is not upheld after awaits. Simultaneous foreground flushes can duplicate the same request as well.

**Fix:** one account/origin single-flight flush; per-row revision/identity comparison before every late remove/write; recheck clear/account/origin generation after each await; cancellation/commit rules shared by enqueue, clear and flush. Test replacement, clear+401, sign-out+origin switch and multiple foreground events.

### M08 — HIGH on affected Android paths, accepted audio rows can exceed readable storage limits

**Evidence:** `mobile/src/audioQueue.ts:31,85` allows a base64 string up to 6,000,000 characters and stores each entire JSON row at `:105–113`. The installed Android AsyncStorage SQLite implementation uses cursor-backed reads. The library maintainer describes the Android CursorWindow read constraint as around 2 MB ([maintainer explanation](https://github.com/react-native-async-storage/async-storage/discussions/640)). A 3–6 MB accepted row can be written but not read; `flushAudioQueue:153` reads outside the per-item try block, so one unreadable row aborts the whole flush. This contradicts the one-item-never-blocks-others comment at `:141–143`.

A temporary simulated CursorWindow regression confirms a permitted 3 MB row remains stored and aborts flushing on read. **This was not reproduced on Android hardware.** At the configured 24 kbps / five-minute recorder settings, an ordinary take is generally below this size, so this is an accepted-input/codec/storage robustness defect rather than a claim that every normal recording breaks.

**Fix:** encrypted filesystem blobs with a small transactional index, or chunking with bounded serialized-byte size; catch reads per item, surface queue failures and avoid silently discarding recordings. The count-cap policy at `:93–103` also silently drops the oldest retained take; expose quota/pending state and obtain an explicit user choice before destructive eviction.

### M09 — HIGH security, recovery scheme negotiation can reveal the raw recovery key

**Evidence:** `mobile/src/recoveryFlow.ts:56–61` first sends the v2 domain-separated verifier, but an unauthenticated server error code `recovery_scheme_mismatch` causes automatic fallback that sends the raw recovery key in the v1 request. It checks only the code, not even the expected status.

The v2 separation was introduced because a server that receives the raw key can derive the recovery seal key and open the wrapped journal data key. A malicious or compromised server can return the mismatch code to a genuine v2 kit and trigger exactly that disclosure. TLS authenticates the server origin, not the honesty of its protocol response. This finding applies to the app's stated hostile-server recovery threat model; it is not an external network interception claim.

**Fix:** encode/authenticate the kit scheme in the locally held recovery kit and select it locally. Never downgrade a v2 kit based solely on a server response. Require a deliberate legacy-kit import/version path and keep v2 proofs permanently v2. Add an adversarial server regression proving no mismatch response can elicit the raw key from a v2 kit. Also use `finally` to zeroize the recovery key and temporary data/auth keys on every failure path.

### M10 — HIGH data preservation, legacy password rotation misses newly added encrypted locals

**Evidence:** `mobile/src/rotation.ts:645–661` handles entry versions, text queue, mood log, question feedback and unlock proof when the v1 data key changes. It does not migrate the encrypted safety plan, pending questionnaire or audio queue introduced later.

After a successful v1 password rotation, safety-plan data reads as absent under the new key; pending questionnaires and retained queued recordings still sealed under the retired key become unreadable/orphaned. The v2 rotation retains its data key and is not affected by this particular defect.

**Fix:** maintain a registry of every data-key-bound store and migrate each atomically/resumably on legacy key rotation. Preserve user-authored safety plans and pending records; do not classify them as disposable caches. Cover rotation with pending text+audio+questionnaire+safety-plan fixtures and power-loss/storage-failure checkpoints.

### M11 — HIGH native contract gap, biometric existence checks retrieve protected secrets

**Evidence:** `mobile/src/biometricUnlock.ts:55–68,109–117` claims omitting `accessControl` makes `getGenericPassword` a quiet metadata read. The installed `react-native-keychain` iOS implementation actually sets `kSecReturnData=true` (`node_modules/react-native-keychain/ios/RNKeychainManager/RNKeychainManager.m:480`) and calls `SecItemCopyMatching:492`; access control is attached to the stored item. A protected item's secret retrieval may authenticate regardless of the missing JS option. Mounts call this from `UnlockScreen.tsx:88` and `SettingsScreen.tsx:223`.

The test mock reproduces the mistaken assumption, so passing tests cannot certify absence of unsolicited biometric prompts. The app also lacks `NSFaceIDUsageDescription` in `mobile/ios/MindPattern/Info.plist`, required by the installed keychain package's Face ID integration instructions (`node_modules/react-native-keychain/README.md:21`). Real Face ID behavior was not run here; expect a permission/integration failure until the purpose string is supplied.

**Fix:** use the library's actual noninteractive existence API/metadata query, ownership metadata appropriate to per-account service naming, and add the Face ID purpose string. Test protected-item existence without a prompt and explicit unlock with a prompt on real iOS hardware, including cancellation, biometric re-enrollment and OS inactive events. Do not claim node mocks validate Keychain access-control semantics.

## Medium-priority defects and privacy/UX weaknesses

### M12 — MEDIUM, long safety-plan fields save successfully and vanish on next read

`mobile/src/safetyPlan.ts:55,79–81` rejects fields longer than 4,000 characters when loading; `:96–103` performs no matching write validation. `mobile/src/screens/SafetyPlanScreen.tsx:200–209` has no `maxLength`. A user can enter 4,001 characters, receive a Saved result, and subsequently get an absent plan. The temporary regression reproduces successful save followed by `loadSafetyPlan(...) === null`.

Validate before write and show a count/helpful limit; use the same exported schema for UI and storage. Distinguish corruption/decryption failure from “no plan” rather than silently presenting empty fields. Plan TextInputs should carry the same sensitive-keyboard flags used by journal text. The saved/loading helper also retains key-copy/plaintext buffers without zeroization after use.

### M13 — MEDIUM, journal text editing destroys original metadata

`mobile/src/screens/HistoryScreen.tsx:82–93` retains several structured/voice fields but does not retain the original payload `created_at` or time-of-day `tod`. `:902–919` re-encrypts edited text using `entry.entryDate` as the created timestamp and only `{energy,sleep,tags}` for structured metadata. Thus a words-only edit changes the original timestamp into a date and drops time-of-day data used by analysis. Preserve the complete decoded payload and apply a typed patch to its text/translation/version fields; regression-test byte/semantic preservation of all other channels.

### M14 — MEDIUM privacy/lifecycle, voice playback can complete after unmount/lock

`mobile/src/screens/HistoryScreen.tsx:291–295` cleans up current playback on unmount, while `:310–320` awaits file creation/decryption and then installs refs/starts the player without a mounted/operation-generation check. An unmount after plaintext scratch-file creation begins but before that promise resolves can run cleanup before the result is installed; its late continuation can then orphan a plaintext file or start audio after the screen/lock transition. Two rapid taps before `playingId` is set can also overlap preparation because it is not a pending-operation guard.

This is a reachable source-level lifecycle race, not a device-reproduced leak. Add a playback operation epoch, cancellation-aware cleanup for late results, key snapshots zeroized in `finally`, and an explicit loading/playing state machine. Test pause/unmount/lock during fetch, decrypt, scratch-write and player creation, and double tap.

### M15 — MEDIUM, account deletion cleanup stops at the first local failure

`mobile/src/screens/SettingsScreen.tsx:370–419` wraps many independent erasure actions in one sequential `try`. If `clearQueue` or another early storage operation fails, later safety-plan, biometric wrap, reminders, credentials and rollback-mark cleanup is not attempted. The catch suppresses the failure and the unconditional deletion dialog at `:421` does not reflect which local erasure failed. The comment says cleanup is attempted in full, but control flow does not do that.

Use independently attempted cleanup (`allSettled` where safe), a durable local erasure tombstone/retry, and an accurate final local-erasure result while acknowledging the already-successful server deletion. Ensure delayed audio work cannot recreate erased rows (M07). Server-side deletion and client-side erasure are distinct outcomes.

### M16 — MEDIUM security/product, recovery kit mutation has no fresh user-presence check

`mobile/src/screens/SettingsScreen.tsx:728–780` creates/replaces or removes a recovery kit using the auth verifier already in an unlocked vault. Its buttons at `:1076,1082` invoke these functions directly, while other destructive settings use the password confirmation card. An unattended unlocked phone can replace/delete the recovery route without knowing the password. Generating a kit also leaves its raw buffer unzeroized.

Require recent password/biometric reauthentication, clear replacement/removal consequences, and a save/confirmation ceremony before enabling a newly generated kit. Keep kit material out of generic UI state where feasible and clear it on screen blur/background; add failure-safe cleanup. This is a user-presence hardening weakness, not proof that an unauthenticated remote attacker can call the endpoint.

### M17 — MEDIUM, runtime language switching is incompletely reactive

`mobile/src/screens/PrivacyScreen.tsx:17–38` resolves all section copy at module load despite shipped manual language switching. `mobile/src/strings.ts:50–58` mutates a global variable without a React subscription. `mobile/App.tsx:38–42` loads the stored choice asynchronously in an effect and does not trigger an associated rerender; already-rendered text can remain in the device language until some unrelated state update. Static privacy sections remain at their initial locale even after a user changes language.

Use a locale context/store with an explicit boot-ready state, resolve catalogs at render, update navigation headers and every mounted screen atomically. Test cold start with an opposite-device stored locale and changing English↔Spanish while Privacy/other screens are mounted. Existing translated catalogs and completeness tests are valuable, but they do not verify render reactivity.

### M18 — MEDIUM, foreground notification taps queue a destination without navigating

`mobile/src/nativeFeatures.ts:463–465` records a foreground tap in a module queue. `mobile/src/navigation.tsx:111–117` consumes that queue only when entering the main flow; a tap while already unlocked in the main flow has no reactive subscriber and does not immediately open Measures. A delayed cold-start initial notification can also arrive after the one-time transition. The unsubscribe returned by `onForegroundEvent` is discarded.

Use navigation readiness plus an observable pending-route queue; route immediately when unlocked, retain intent while locked, and dispose the listener. Verify cold start, foreground, already-unlocked background return, locked return, delayed bridge result and account changes on both OSes.

### M19 — MEDIUM readiness, native assets/configuration remain placeholders

`mobile/src/api/client.ts:99` still uses `https://api.mindpattern.example` as the production default. It is explicitly documented as a placeholder, not an exposed secret, but a fresh release install cannot authenticate there. The override lives in authenticated Settings, so there is no first-login repair path. Make release CI reject the placeholder and verify the intended deployed origin.

The iOS AppIcon `Contents.json` has no image filenames and no PNG artwork exists under the app asset catalog. The iOS bundle identifier still uses the React Native example template. `LaunchScreen.storyboard` still displays MindPattern / Powered by React Native while JS branding says Fathom. These are release configuration/brand readiness items; lack of a developer team/private keystore in source is correct and is not itself a vulnerability. Add signed archive/install validation and asset/identifier checks rather than checking only that the project directory exists.

### M20 — MEDIUM privacy, iOS capture shield does not initialize existing capture state

`mobile/ios/MindPattern/AppDelegate.swift:62–68` observes capture changes, but does not call `captureStateChanged()` at initialization. Launching the app while screen recording/mirroring is already active can leave foreground content uncovered until a capture-change event occurs. The separate inactive snapshot shield is a good design but does not initialize the recording shield. Evaluate initial state after the window is ready, re-evaluate when becoming active, and test recording before launch/after launch/with background transitions. No capture behavior was hardware-tested in this audit.

## Additional findings from completing the remaining production-source reads

### M21 — HIGH recovery/export functionality, decrypt-export tool always uses a v1 key

`mobile/tools/decrypt_export.mjs:131–132` derives the data key directly from the password master key for every export. It never dispatches on `key_scheme` or unwraps the stored `wrapped_data_key`, despite current registrations using a random v2 data key. A correct password therefore cannot open a normal v2 account export through this published tool. The shipping crypto engine does provide a valid Node fallback; native import failure is **not** the finding.

Implement version-aware export key opening with the same validated envelope parameters/AAD as the app; add v1/v2/new-password/recovery-after-reset export fixtures. The tool's KDF input check at `:120–128` only enforces a minimum, allowing a malicious/corrupt bundle to request extreme work; apply the library's maximum and validate scheme/version/salt before derivation. Its prompt at `:46–50` uses plain readline and can visibly echo a password; the documentation should accurately describe that behavior and offer a proper concealed prompt or safe input mechanism.

### M22 — HIGH correctness, edit conflict retry can report success before it succeeds

`mobile/src/screens/HistoryScreen.tsx:999–1009` defines a `retry(): void` that starts `void applyEdit().then(finishEdit)`. When the newer text is equal to the draft or cannot be decrypted, `:1043` calls that nonawaited retry and then execution reaches the unconditional `await finishEdit(...)` at `:1064`. The app can show Updated, close the editor and display unsaved words before the actual retry resolves; a retry failure then leaves UI/draft state incorrectly committed. The successful retry can run finishEdit twice.

Furthermore, `:996–997` explicitly turns inability to decrypt the current server version into automatic overwrite rather than a comparison/refusal. The “keep theirs” branch at `:1032` only applies their text to the old metadata, leaving other changed payload channels stale. Make retry return an awaited result and run one completion only after acknowledged commit; preserve the draft on failure. Refuse automatic overwrite when the newer payload cannot be authenticated/read, and apply the complete current decoded payload when keeping theirs. These are static control-flow findings; no additional reproduction run was requested during coverage completion.

### M23 — MEDIUM reminder reliability, future questionnaire cadence is never scheduled

`mobile/src/reminderSync.ts:75–78` cancels the measure reminder whenever the selected 2/4/8-week interval is not yet due and schedules only when app-side sync runs after it is overdue. After questionnaire completion there is no future notification armed. A user who stops opening the app will not receive the intended due-date nudge because no app execution occurs to schedule it. This is an explicit implementation policy, but it fails the product purpose of a cadence reminder.

Calculate and schedule the next due timestamp immediately after completion/opt-in/interval change; reconcile/rearm it on app start without requiring the user to already be overdue. Validate timezone/DST and cancellation on real devices. `SettingsScreen.tsx:472–480,499–507` also suppresses preference-write failures then updates the selected time/interval in UI; show failure or roll back selection so the display reflects persisted settings.

### M24 — MEDIUM release configuration, app privacy manifest is not a bundle resource

`mobile/ios/MindPattern.xcodeproj/project.pbxproj:21` creates a file reference for `PrivacyInfo.xcprivacy`, but there is no corresponding PBXBuildFile entry or Resources membership. The app Resources phase at `:160–169` lists only LaunchScreen and Images. Thus the app-level manifest appears omitted from its archive rather than merely incomplete. Dependency privacy manifests are separate and do not prove this app resource is included.

Add target resource membership and inspect a signed archive/installed bundle for the app manifest. This source-level target configuration finding is not a claim that an App Store upload was attempted or rejected. Also remove the dangling nonexistent MindPatternTests target from the shared Xcode scheme or supply a real native test target before treating its Test action as validation.

### M25 — MEDIUM insight meaning/localization, specific descriptions are unreachable

`mobile/src/screens/InsightsScreen.tsx:377–392` returns immediately for temporal/mood-correlation/link kinds. The later sleep-quality branches at `:441–454` and activity-tag branches at `:464–478` check those same kinds and therefore never execute. Users get generic descriptions instead of the domain-specific sleep/tag copy. At `:383`, the no-direction fallback maps a negative mood delta to “higher” and a positive delta to “lower”; a raw direction string is passed straight to the translation lookup rather than mapped to its locale key. Normal records with an explicit direction avoid the fallback polarity issue, but Spanish descriptions can still retain English “higher/lower”.

Dispatch source/channel-specific descriptions before generic kind branches, normalize direction once and use translated keys. Contract-test all source × channel × kind combinations and missing-direction records against expected interpretation. No new clinical efficacy claim follows from this UI source review.

## Independent v2 export confirmation

After the complete source review, the primary audit built a valid synthetic v2 envelope/random-data-key entry and independently decrypted both. The documented CLI, run from the mobile working directory with the correct synthetic password, decrypted zero of one entry and exited 1. See [CLI evidence](validation-logs/audit-v2-export.log). This confirms M21 at runtime. The server export omits the username required by the existing envelope AAD, so the repair also needs a local username prompt or compatible export/recovery format. The tool currently ignores kept audio objects entirely.

## UI/UX and accessibility evidence gaps

The app has a coherent theme/token approach, accessible labels/roles on core buttons, sensible touch minimums, translated English/Spanish catalogs, offline crisis resources and calm error/status language. Existing theme contrast tests are a useful positive control. These should be retained.

However, the source uses a `SafeAreaProvider` without consuming inset values in app screens/navigation; `mobile/src/components/BottomNav.tsx:138` hard-codes 8/10 pixels bottom padding. Android enables edge-to-edge and targets modern APIs; iPhone home indicators/notches and Android gesture navigation need actual screen-level layout verification. This is a likely layout risk requiring device evidence, not a claim from a screenshot.

Six bottom navigation items use small labels; some controls cap font scaling at 1.3, and fixed-width questionnaire choices use `numberOfLines={2}`. The design needs screen-reader focus order, 200%/maximum text-size, localization expansion, reduced motion, orientation and keyboard-open checks on small and large devices. Convert dense horizontal answer rows to adaptable stacked choices where needed. Avoid shrinking text to rescue layouts.

Safety-plan unsaved-change protection should handle native navigation gestures/header back as well as Android BackHandler and custom buttons. Background vault locking unmounts screens; user-authored drafts and structured selections should have an explicit encrypted durable draft policy. An in-memory journal draft is not process-death recovery. History currently relies on server reads rather than a complete local encrypted history cache: that can be a valid privacy/storage tradeoff, but users must understand which previously saved material works offline.

Crisis support should remain a one-tap offline path from locked/authenticated flows. Any detector/PHQ threshold should offer help without diagnosing, falsely claiming monitored emergency response, or automatically contacting someone. Treat lexicon/sentiment output as uncertain reflection; validate false-positive/false-negative performance across language, quotations, third-person references, idioms and dialects with clinical and lived-experience review before making safety efficacy claims.

## How to turn this into an excellent application

### First: make the existing promises true

1. Fix M01/M02/M04/M05 immediately, configure a real production origin and ship only after a signed native install opens both platforms.
2. Fix voice queue dependency ordering, replacement/clear races and storage architecture; show per-record pending/uploaded/failed status and allow user-controlled retry/export. Do not silently remove a kept recording or safety plan.
3. Remove recovery downgrade negotiation based on server error codes; test recovery/password rotation across every local encrypted store and real API schemas.
4. Correct HealthKit/Face ID integration and replace mock assumptions with hardware acceptance tests. Treat the existing device checklist as unexecuted until actual results are recorded.

### Then: establish a reliable technical core

Use typed decoded API schemas at one boundary; no `any` return type for sessions, authentication, recovery, paging or encrypted payload metadata. Model authentication/vault/session/rotation, voice capture/playback and sync as explicit state machines with operation epochs. Keep one transactional ownership/generation mechanism across enqueue, clear, sign-out, account switch and late network completion. Maintain a central registry of all data-key-bound stores, their versions, migration handlers, erase handlers and key-rotation policies.

Split the 1,400-line Settings screen and large History/API modules into coherent feature/domain units. Replace historical “audit fix” comments and source-string pin tests with concise invariants and behavioral contract tests. Add actual backend-client integration tests for every public JSON response, particularly recovery and conflict handling. Test failures at every awaited persistence/network boundary, including a server commit followed by a lost response. Preserve unknown payload fields through edits/migrations. Add native release builds, boot smoke tests and critical journeys to CI; current node suites should remain a fast layer.

### Then: earn trust through polished, measurable product outcomes

Focus on a small number of exceptionally dependable journeys: start safely, reflect quickly, recover every saved entry, understand patterns with uncertainty, share deliberately and retrieve crisis support offline. Reduce navigation density and long Settings overload; organize settings by user intent with progressive disclosure. Make syncing, retention, Health mirroring and server processing understandable in plain language. Provide clear control over sensitive drafts/recordings and durable export/recovery tools.

Run formative usability sessions with users including low digital confidence, visual/motor impairments and people experiencing distress; have clinicians and privacy reviewers evaluate wording and risk boundaries. Instrument consented, redacted crash/performance metrics without journal content. Establish explicit gates: no launch failures; no acknowledged-write data loss; complete recovery success under supported conditions; verified deletion; acceptable cold-start/save latency; screen-reader and large-text completion of all core journeys; and published boundaries for detection accuracy. Define targets from measured device/backend baselines rather than inventing numbers.

“Best ever” is not a verifiable acceptance criterion. A trustworthy app with measured reliability, accessible flows, clinically responsible boundaries and user-controlled privacy is a concrete goal this project can pursue. The existing engineering investment makes that plausible, but native release truth and preservation of sensitive user data must come first.
