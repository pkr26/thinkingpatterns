# On-device verification checklist — MindPattern mobile

An EXECUTABLE checklist for an operator with real iOS and Android
hardware. Nothing here has been executed as part of the audit remediation
that produced it — every row below is to be run, in order, on a release
(or release-configured debug) build before that build ships. Unit and
mutation suites in `tests/` pin the JS-side contracts; these rows pin
what only the OS and silicon can answer: Keychain/Keystore custody
semantics, reinstall behavior, notification delivery, screenshot
blocking, and reconnect flushing.

Run the whole file per platform per release candidate. A row that fails
stops the release: write the observed behavior under "Actual result",
file it, and do not sign. Fill in every blank; a blank signature is a
row that did not happen.

- Build under test (commit + version): ______________________________
- iOS device + OS version: __________________________________________
- Android device + OS version: ______________________________________
- Operator: ____________________  Date started: ____________________

---

## 1. Biometry-current-set: the data-key wrap dies on biometry re-enrollment

The biometric data-key wrap (`src/biometricUnlock.ts`) requests
`BIOMETRY_CURRENT_SET` (Keychain access control / Keystore-bound
invalidation). Contract: re-enrolling ANY biometric on the device must
invalidate the wrap, and the app must fall back to the password unlock
path — never a crash, never a stale wrap that still opens.

**iOS (Face/Touch ID):**

1. Sign in, unlock once, then enable biometric unlock in Settings
   (password card → enable).
2. Kill the app, relaunch, reach the unlock gate, unlock with biometry —
   confirms the wrap works BEFORE invalidating it.
3. Go to iOS Settings → Face ID & Passcode → Reset Face ID (or enroll a
   different fingerprint under Touch ID), then relaunch MindPattern and
   reach the unlock gate.
4. Attempt the biometric unlock affordance.

Expected: the wrap is refused by the OS (prompt fails or the option
reports unavailable); the PASSWORD unlock path still opens the vault;
no crash; the Settings biometric toggle honestly reflects that the wrap
is gone (re-enabling it is possible after unlocking).

Actual result: ______________________________________________________

**Android (fingerprint/face):**

1. Sign in, unlock once, enable biometric unlock in Settings; relaunch
   and confirm biometric unlock works.
2. System Settings → Security → delete ALL enrolled fingerprints (or
   enroll a new one), relaunch MindPattern, reach the unlock gate.
3. Attempt biometric unlock.

Expected: Keystore invalidates the key bound to the old biometry set —
the prompt fails or the option reports unavailable; password unlock
still works; no crash.

Actual result: ______________________________________________________

Verified by: ____________________  Date: ____________________

## 2. Uninstall / reinstall — nothing survives that should not

1. Sign in, unlock, write one entry, enable the reminder and (if
   available) biometric unlock, and note the server URL shown at login.
2. Uninstall the app (do NOT delete the account). Reinstall, launch.
3. Attempt to sign in with the same username/password.

Expected: the app behaves as a FRESH install — the sign-in screen shows
the configured server URL (re-enter or re-select it as this build
requires), sign-in succeeds, and the journal written in step 1 decrypts
after unlock (it re-syncs from the server). The session device key, the
biometric wrap, the cached salt, the offline queue, the mood log and the
reminder preference do NOT carry over: no offline unlock offer, no
biometric unlock toggle left on, no reminder fires without re-enabling.
`allowBackup=false` (Android) and the `ThisDeviceOnly` Keychain class
(iOS) are exactly what this row exercises.

Actual result: ______________________________________________________

Verified by: ____________________  Date: ____________________

## 3. Daily reminder: exactly ONE notification survives N restarts

Pins the duplicate-reminder fix (2026-09-26 audit item 1): the reminder is
scheduled under a stable notification id with cancel-before-create, so
repeated session starts must converge to one schedule, not stack.

1. Enable the daily reminder (Settings → Remind me), pick a time a few
   minutes in the future.
2. Force-quit and relaunch the app FIVE times (each start reconciles the
   schedule — `reminderSync.syncReminderSchedule`).
3. iOS: Settings → Notifications → MindPattern shows the pending style
   only; wait past the chosen time. Android: the notification drawer at
   the chosen time.
4. Also change the reminder time once and let it fire again.

Expected: exactly ONE reminder fires at the chosen time (not two, not
five — the pre-fix bug stacked one schedule per restart); after the time
change the reminder fires at the NEW time only. Toggling the reminder
off stops all future delivery.

Actual result: ______________________________________________________

Verified by: ____________________  Date: ____________________

## 4. FLAG_SECURE — no screenshots, no recents preview (Android)

`MainActivity` sets `FLAG_SECURE` at the Activity level
(mobile/README.md §3.2): screenshots and the app-switcher snapshot are
blocked APP-WIDE on Android. iOS has no equivalent; the native
app-switcher cover (README §2.6) is the iOS defense and is covered by
its own row in the iOS checklist — this row is Android-only.

1. Open History, open any entry (decrypted journal content on screen).
2. Take a screenshot (power + volume-down).
3. Background the app and inspect the recents/app-switcher carousel.
4. Repeat 1–3 on the login screen (no decrypted content).

Expected: the screenshot is blocked by the OS (Android shows a
"screenshot prevented" toast or saves nothing); the recents thumbnail is
blank/the system placeholder on EVERY screen, not just journal screens
(the accepted app-wide tradeoff — documented and intended for a
mental-health journal). On iOS, screenshots remain possible (OS
limitation, documented) and the switcher shows the opaque cover.

Actual result (Android): ____________________________________________

iOS switcher cover (informational, per README §2.6): ______________

Verified by: ____________________  Date: ____________________

## 5. Offline queue flush on foreground

1. Sign in, unlock, then enable airplane mode.
2. Write and save TWO entries — each shows the quiet "saved offline"
   status; the offline queue now holds both (ciphertext only).
3. Keep the app foregrounded, disable airplane mode.
4. Background the app, wait 10 seconds, foreground it.

Expected: foregrounding triggers the reconnect flush
(`flushQueueOnReconnect`); both entries upload; the History screen
(after pull/load) shows them; the queue is empty afterwards. A second
foreground cycle uploads nothing new. With a wrong/changed server URL
selected in between, the queued rows must REFUSE to send (origin pin)
and stay queued rather than ride the new origin.

Actual result: ______________________________________________________

Verified by: ____________________  Date: ____________________

---

Completion: a release candidate passes when all five rows above are
signed on BOTH platforms. Attach this file (or a copy with the blanks
filled) to the release notes — `npm run verify:native-release` output
belongs next to it (the static half of native verification; this file
is the dynamic half).
