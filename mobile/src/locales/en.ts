/**
 * The English catalog — the source of truth for every user-visible string
 * in the app (2026-09-19 i18n wave). Keys are namespaced by screen
 * (entry.*, crisis.*, question.*, …) with a small common.* pool for copy
 * shared across screens.
 *
 * Rules carried over from the audit:
 *  - calm, honest, non-shaming copy; no advice, no diagnosis;
 *  - crisis phone numbers and URLs are never translated (identical in
 *    every locale by design);
 *  - "{name}" placeholders are interpolated by t() in src/strings.ts.
 */

export const en: Record<string, string> = {
  "recovery.onlineUnlockRequired": "Your new password is active. Offline unlock could not be prepared on this device; connect to your server for the next unlock.",
  "unlock.rotationPending": "A password change was interrupted. If the new password is already active, unlock with it. Otherwise enter your old password above and the same new password below to finish safely.",
  "unlock.rotationPassword": "Previously chosen new password",
  "unlock.finishRotation": "Finish interrupted password change",
  "unlock.rotationFinished": "The password change is complete. Unlock with your new password.",
  "settings.rotationRecoveryReset": "A legacy data-key change invalidates the previous recovery kit. Create and save a new recovery kit after signing in.",
  "login.changeServer": "Change server",
  "login.saveServer": "Save server",
  "settings.localCleanupIncomplete": "Your server account is deleted. Some device cleanup remains; Fathom will retry it on the next start.",
  "settings.savedAudioQueue": "{count} encrypted recordings saved on this device; {attention} need attention. Upload failures never delete your saved copy.",
  "settings.retryAudio": "Retry saved recordings",
  "settings.savedAudioItem": "Recording {number} · {date}",
  "settings.recordingDateUnavailable": "date unavailable",
  "settings.audioNeedsAttention": "Upload needs attention. Retry, export an encrypted copy, or remove it when you are ready.",
  "settings.exportAudio": "Export encrypted recording {number}",
  "settings.exportFailedTitle": "Export failed",
  "settings.removeAudio": "Remove saved recording {number}",
  "settings.removeAudioTitle": "Remove this saved recording?",
  "settings.removeAudioBody": "This removes the device's saved copy. Export an encrypted copy first if you want to keep it. Your journal entry stays saved.",
  "settings.removeAudioConfirm": "Remove recording",
  "insights.strengthNote": "Observation strength is a heuristic, not diagnostic probability.",
  "history.unreadableConflict": "The saved version could not be verified. Reload before choosing which edit to keep.",
  "insights.ev.basedOnEntries": "{count} journal entries",
  "insights.ev.entries": "Entries in this window",
  "settings.reauthRecoveryTitle": "Verify your password to change your recovery kit",
  "settings.recoveryReplaceWarning": "Replacing your kit immediately invalidates the old recovery key. Keep this screen open until you save the new kit.",
  "recovery.useLegacy": "Use a legacy v1 kit (sends its key to your server)",
  "recovery.legacySelected": "Legacy v1 selected — tap to use v2",
  // ---------------------------------------------------------------- common
  "common.notNow": "Not now",
  "common.cancel": "Cancel",
  "common.continue": "Continue",
  "common.ok": "OK",
  "common.tryAgain": "Try again",
  "common.back": "Back",
  "common.delete": "Delete",
  "common.deletePermanently": "Delete permanently",
  "common.finalConfirmation": "Final confirmation",
  "common.day": "day",
  "common.days": "days",
  "common.accountMissing": "account id missing — sign in again",
  "common.sessionDamagedTitle": "Session damaged",
  "common.wrongPassword": "Wrong password.",
  "common.passwordPlaceholder": "password",
  "common.passwordA11y": "Password",
  "common.passwordConfirmA11y": "Password confirmation",
  "common.verifying": "Verifying…",
  "common.confirmWithPassword": "Confirm with password",
  "common.couldNotVerifyTitle": "Could not verify",
  "common.reauthLocked": "The vault is locked — unlock again first.",
  "common.reauthNoAccount": "No saved account on this device — sign in again.",
  "common.reauthOffline": "Cannot verify your password offline right now — try again when online.",
  "common.passwordMismatchTitle": "That password didn't match",
  "common.passwordMismatchBody": "Check it and try again — nothing was changed.",
  "common.sessionExpiredTitle": "Session expired",
  "common.unlockAgainBody": "Please unlock again.",
  "common.couldNotCompleteTitle": "Could not complete",
  "common.neverWrongMove": "Talking to a professional is never a wrong move.",
  // 2026-09-27: the local safety plan's action label — shared by the crisis
  // screen link, the crisis dialogs' third button and the Settings row.
  "common.makeSafetyPlan": "Make a safety plan",
  "common.streakOne": "Writing streak: {count} day",
  "common.streakMany": "Writing streak: {count} days",

  // ---------------------------------------------------------------- errors
  "errors.offline": "Couldn't reach the server — check your connection.",
  "errors.sessionExpired": "Session expired — please unlock again.",
  "errors.forbidden": "The server refused that request.",
  "errors.notFound": "That isn't on the server (anymore).",
  "errors.conflict": "That conflicts with something the server already has.",
  "errors.tooLarge": "That's more data than the server can accept.",
  "errors.rateLimited": "Too many attempts — wait a moment, then try again.",
  "errors.serverError": "The server hit a problem — try again in a moment.",
  "errors.rejected": "The server didn't accept that request.",
  "errors.generic": "Something went wrong — try again.",

  // ------------------------------------------------------------ nav / buttons
  "nav.today": "Today",
  "nav.history": "History",
  "nav.patterns": "Patterns",
  "nav.question": "Question",
  "nav.settings": "Settings",
  "nav.getHelp": "Get help",
  "nav.a11y": "Main navigation",
  "nav.getHelpA11y": "Get help — crisis resources",
  // 2026-09-26 audit M-M4: the navigator's screen titles resolve through
  // the catalog (they were hardcoded English bypassing i18n). nav.question
  // stays the bottom-tab label; the Question SCREEN header reads longer.
  "nav.questionTitle": "One question",
  "nav.therapist": "My therapist",
  "nav.measures": "Wellbeing measures",
  "nav.privacy": "Privacy",
  "buttons.needHelp": "Need help now? Crisis resources",

  // -------------------------------------------------------------- calendar
  "calendar.a11y": "Calendar, {month}. Dots mark journaled days.",
  "calendar.prevMonth": "Previous month",
  "calendar.nextMonth": "Next month",
  "calendar.dayJournaled": "{date}, journaled",
  "calendar.dayJournaledSelected": "{date}, journaled, selected",
  "calendar.dayNoEntry": "{date}, no entry",

  // ---------------------------------------------------------------- crisis
  // SAFETY-CRITICAL copy: numbers and URLs never change per locale.
  "crisis.title": "If you are thinking about harming yourself",
  "crisis.subtitle":
    "Please reach out right now. These services are free, confidential, and staffed by trained people — 24 hours a day.",
  "crisis.whatToExpect":
    "What to expect when you call or text: a trained counselor answers, and you can say as much or as little as you want — there is no script and no wrong way to start.",
  "crisis.openFailedTitle": "Couldn't open it from here",
  "crisis.call988": "Call or text 988",
  "crisis.call988.detail": "988 Suicide & Crisis Lifeline — call 988 or text it, any time",
  "crisis.call988.fallback": "You can still dial or text 988 from your phone — it is free and answers 24/7.",
  "crisis.text741741": "Text HOME to 741741",
  "crisis.text741741.detail": "Crisis Text Line — text conversation with a trained counselor",
  "crisis.text741741.fallback": "You can still text HOME to 741741 from your messages app.",
  "crisis.chat": "Chat online at 988lifeline.org",
  "crisis.chat.detail": "The same lifeline, in your browser — no phone call needed",
  "crisis.chat.fallback": "You can still visit 988lifeline.org/chat in a browser.",
  "crisis.emergency": "Call 911 (US)",
  "crisis.emergency.us": "Call 911",
  "crisis.emergency.detail": "If you are in immediate danger or have already hurt yourself",
  "crisis.emergency.fallback": "You can still dial 911 from your phone.",
  "crisis.findhelpline": "Open findahelpline.com",
  "crisis.findhelpline.detail": "Open findahelpline.com — crisis lines worldwide",
  "crisis.findhelpline.fallback": "You can still visit findahelpline.com in a browser.",
  // The local safety plan (2026-09-27): a supplement AFTER the resources,
  // never a gate before them. The link renders only while the vault is
  // unlocked; the resources above never depend on it.
  "crisis.makePlanA11y": "Make a safety plan — private, encrypted on this device",
  "crisis.makePlanNote": "Private to you, encrypted on this device — write what helps you through.",
  "crisis.localeNote": "These are US services. Outside the US, find your local line at findahelpline.com.",
  "crisis.regionNote": "Your region doesn't look like the US — find your local line first:",
  "crisis.usServicesNote": "In the US, these are the national services (988 and 741741 are US-only):",
  "crisis.go": "Go",
  "crisis.actionA11y": "{label} — {detail}",
  "crisis.disclaimer":
    "Fathom is a journal that shows you your own patterns. It is not therapy, not a medical device, and not an emergency service. Talking to a professional is never a wrong move.",

  // ---------------------------------------------------------------- unlock
  "unlock.title": "Locked",
  "unlock.body":
    "Re-enter your password to unlock this device. Your writing syncs encrypted, with account and entry metadata. Pattern analysis temporarily gives the server access to your journal key. Optional voice transcription and translation send the audio or text you choose for that purpose.",
  "unlock.biometric": "Unlock with biometrics",
  "unlock.biometricFailed": "Biometric unlock didn't work — your password always works below.",
  "unlock.button": "Unlock",
  "unlock.signOutInstead": "Sign out instead",
  "unlock.failedTitle": "Unlock failed",
  "unlock.noAccount": "no saved account on this device — please sign in",
  "unlock.offlineNotEnabled":
    "offline unlock is not enabled on this device yet — sign in once while online to enable it",
  // v2 key envelope (2026-09-26): the password was accepted (online) or the
  // cached envelope was readable, but the envelope itself would not open or
  // is unusable — a calm server/data message, never "wrong password".
  "unlock.envelopeFailed":
    "your account's key envelope could not be opened on this server. Nothing was changed — try again, and contact support if it repeats.",
  // independent audit 2026-09-27 (P2): the online login succeeded but the
  // key-scheme fetch failed and all this device has is a STALE scheme marker
  // (or nothing). A marker alone cannot authorize deriving v1 keys: today it
  // is safe only because v1→v2 wraps the same data key, and any future
  // scheme rotation would turn this into a silent wrong-key write. Refused
  // with honest retry copy — nothing was unlocked or changed.
  "unlock.schemeUnconfirmed":
    "We couldn't confirm how your account's encryption is set up right now. Check your connection and try again in a moment — nothing was unlocked and nothing was changed.",

  // ----------------------------------------------------------------- login
  "recovery.title": "Recover your journal",
  "recovery.subtitle": "Use the recovery key from your kit. Your words come back; only the password changes.",
  "recovery.usernameLabel": "Username",
  "recovery.keyLabel": "Recovery key",
  "recovery.keyHint": "Paste the base64 key exactly as your kit shows it.",
  "recovery.newPasswordLabel": "New password (12+ characters)",
  "recovery.confirmLabel": "Confirm new password",
  "recovery.action": "Recover and set new password",
  "recovery.missingFields": "Enter your username and the recovery key first.",
  "recovery.passwordTooShort": "The new password needs at least 12 characters.",
  "recovery.passwordMismatch": "The two new passwords do not match.",
  "recovery.doneBody": "Recovered. Your journal is unlocked and the new password is active.",
  "recovery.failedBody": "Recovery did not complete. Check the key and username, and try again.",
  "recovery.backToLogin": "Back to sign in",
  "login.useRecoveryKey": "Forgot password? Use a recovery key",
  "login.subtitle": "Your patterns, from your words. Encrypted on this device.",
  "login.usernamePlaceholder": "username",
  "login.usernameA11y": "Username",
  "login.confirmPlaceholder": "confirm password",
  "login.confirmA11y": "Confirm password",
  "login.strength": "Password strength: {label}.",
  "login.strength.weak": "weak",
  "login.strength.fair": "fair",
  "login.strength.strong": "strong",
  "login.strengthWeakHint": "Longer is stronger — aim for a short sentence or several words.",
  "login.strengthFairHint": "Good start — more length or a symbol makes it stronger.",
  "login.mismatchInline": "Passwords don't match.",
  "login.mismatchTitle": "Passwords don't match",
  "login.mismatchBody": "Type the same password twice. Keep it safe, and enroll a recovery kit after signing in.",
  "login.policyShortTitle": "Password too short",
  "login.policyVarietyTitle": "Password needs more variety",
  "login.policyMin": "Use at least 12 characters — this password derives your encryption keys.",
  "login.policyVariety": "Use a 16-character passphrase, or 12+ characters from at least three character types.",
  "login.policyCommon": "That password is too easy to guess. Avoid common words, repeated characters, and keyboard sequences.",
  "login.serverLabel": "Server: {server}",
  "login.serverA11y": "Selected server address",
  "login.serverChangedWarning":
    "This server is different from the one you usually sign in to. Verify the address before entering credentials; only use a server you trust.",
  "login.serverChangedA11y": "Warning: server address changed",
  "login.trustThisServer": "I trust this server",
  "login.policyHint":
    "Choose a password of at least 12 characters — a 16-character passphrase, or 12–15 characters from at least three character types.",
  "login.noReset":
    "An enrolled recovery kit can reset a forgotten password. Without your password or a saved recovery kit, no one — including us — can recover your journal.",
  "login.signIn": "Sign in",
  "login.createAccount": "Create account",
  // AGE GATE (2026-09-27, clinical): registration requires an explicit 18+
  // self-declaration. Safety-critical copy — keep it a plain statement of
  // fact, identical in meaning in every locale.
  "login.ageConfirm": "I am 18 or older",
  "login.ageConfirmA11y": "Age confirmation — I am 18 or older",
  "login.switchToRegister": "New here? Create an account",
  "login.switchToSignIn": "Already have an account? Sign in",
  "login.registerFailedTitle": "Couldn't create account",
  "login.signInFailedTitle": "Sign in failed",
  "login.badCredentials": "That username or password didn't match.",
  "login.usernameTaken": "That username is already taken. Try another, or sign in instead.",
  // L-65: the account WAS created but a later step (session write, unlock
  // proof) failed — the fix is signing in, not re-registering (which would
  // 409 on the taken username and strand the user).
  "login.registerPartialTitle": "Account created",
  "login.registerPartialBody":
    "Your account was created, but this device couldn't finish signing you in. Switch to sign-in and use your new username and password.",
  // v2 key envelope (2026-09-26): the password was accepted online, but the
  // account's key envelope did not open under it on this server — not a
  // wrong-password message.
  "login.envelopeFailed":
    "Your password was accepted, but this account's key envelope could not be unlocked on this server. Nothing was changed — try again, or contact support if it repeats.",
  "login.envelopeUnrecognized":
    "We couldn't verify your encryption key — the server sent a response this app doesn't understand. Nothing was changed; updating the app may help.",

  // ------------------------------------------------------------- onboarding
  "onboarding.panel1Title": "Write each day",
  "onboarding.panel1Body":
    "After 30 days of writing, the app shows you patterns too slow to notice on your own — every one with the evidence behind it. Never advice, never a diagnosis.",
  "onboarding.panel2Title": "Your words stay yours",
  "onboarding.panel2Body":
    "Your entries are encrypted on this device before upload. Your password protects the encryption key; the server stores ciphertext. For an analysis or a key migration you explicitly start, the relevant key is used once — held in memory for up to 5 minutes, then destroyed. It is never stored.",
  "onboarding.panel3Title": "Keep your password safe",
  "onboarding.panel3Body":
    "Keep your password safe. You can enroll and save a recovery kit in Settings to reset a forgotten password. Without either, no one, including us, can recover your journal.",
  "onboarding.stepOf": "{current} of {total}",
  "onboarding.remindQuestion": "Want a gentle reminder each day? You can change it anytime in Settings.",
  "onboarding.readPrivacy": "Read the privacy policy",
  // 2026-09-27: the age floor moved to 18 with the registration age gate
  // (login.ageConfirm) — the onboarding line states the same floor so the
  // two never disagree.
  "onboarding.ageNotice": "Fathom is for people 18 and older — by continuing you confirm that you are.",
  "onboarding.start": "I understand — start writing",
  "onboarding.continueA11y": "Continue to panel {next} of {total}",

  // ---------------------------------------------------------------- privacy
  "privacy.headline": "Privacy, in plain language",
  "privacy.s1Title": "What is encrypted",
  "privacy.s1Body":
    "Journal entries and observations are encrypted on this device before upload. New accounts use a random data key protected by a password-wrapped envelope; legacy accounts derive their data key from the password. An enrolled recovery kit lets you reset a forgotten password. Without the password or a saved recovery kit, we cannot recover your journal.",
  "privacy.s2Title": "What the server sees",
  "privacy.s2Body":
    "Your username, the calendar dates you wrote on, when each entry arrived, and how large each encrypted entry is. A leak of the server's database reveals when and how much you wrote — never what.",
  "privacy.s3Title": "Temporary server decryption",
  "privacy.s3Body":
    "The server can decrypt entries during an analysis you explicitly start. Analysis, key migration and recovery verification use temporary key sessions: relevant keys are sent over an encrypted connection, kept in memory for up to 5 minutes, and never persisted by the server. A v2 recovery kit's raw key stays on your device; the legacy recovery screen explains its different server trust requirement.",
  "privacy.s4Title": "Optional AI analysis",
  "privacy.s4Body":
    "Off by default for every account. If you turn it on, your decrypted entries are sent to a third-party AI provider chosen by the server operator, and that provider's data-retention policy applies. Turning it on asks for your password, so a borrowed phone cannot change it.",
  "privacy.s5Title": "Deleting your data",
  "privacy.s5Body":
    "Deleting your account removes your entries, patterns, and account from the live database. Database backups and server logs expire on the operator's own schedule — deletion cannot reach back into them. An exported bundle includes everything and stays yours to keep or delete.",
  "privacy.footnote": "This policy lives inside the app — reading it needs no connection and leaves no trace anywhere.",

  // ------------------------------------------------------------------ entry
  "entry.daysToPatterns": "{active}/{total} days to your patterns",
  "entry.progressLoading": "Checking your writing days…",
  "entry.progressUnavailable": "Your writing-day count is unavailable right now",
  "entry.progressRetry": "Refresh writing days",
  "entry.patternsUnlocked": "Patterns unlocked",
  "entry.progressA11y": "Progress toward your patterns: {done} of {total} days",
  "entry.wroteToday": "Already wrote today",
  "entry.draftRestored": "Draft restored",
  "entry.deviceDraftNote": "Typed drafts are backed up encrypted on this device. Unsaved recordings are not included.",
  "entry.deviceDraft.loading": "Checking for an encrypted draft…",
  "entry.deviceDraft.saving": "Backing up this draft…",
  "entry.deviceDraft.saved": "Encrypted draft saved on this device",
  "entry.deviceDraft.error": "Draft backup failed. Your words are still here; the previous backup was kept. Retry before closing.",
  "entry.deviceDraft.unreadable": "The previous encrypted draft could not be read. It was kept. Retry to recover it; this editor is not backed up yet.",
  "entry.deviceDraft.cleanup-error": "Your entry was saved, but its old draft could not be removed. It may reappear after restarting.",
  "entry.retryDeviceDraft": "Retry draft backup",
  "entry.deviceDraftConflict": "A saved draft was found after you started editing. Restore it, or replace that backup with this editor.",
  "entry.restoreDeviceDraft": "Restore saved draft",
  "entry.keepCurrentDraft": "Back up current editor instead",
  "entry.ramDraftConflict": "Your earlier editor is also available, including its check-in details. Restore it or keep these new edits.",
  "entry.restoreRamDraft": "Restore earlier editor",
  "entry.keepRamCurrent": "Keep these new edits",
  "entry.readyBody":
    "{days} days of writing — your patterns are ready for a first look. Not everything will have surfaced yet: patterns earn their place as evidence builds, and whatever shows up comes with the days behind it.",
  "entry.seePatterns": "See your patterns",
  "entry.seePatternsA11y": "See your patterns",
  "entry.dismissReadyA11y": "Dismiss the patterns-ready notice",
  "entry.startWith": "Start with: {chip}",
  "entry.placeholder": "What's going on today?",
  "entry.journalA11y": "Journal entry",
  "entry.charCount": "{current} / {max}",
  "entry.hideKeyboard": "Hide keyboard",
  "entry.showDetails": "Add details (optional)",
  "entry.hideDetails": "Hide details",
  "entry.detailsAdded": "Details added: {channels}",
  "entry.detailsAddedA11y": "Details added: {channels}. Tap to show details.",
  "entry.channelMood": "mood",
  "entry.channelEnergy": "energy",
  "entry.channelSleep": "sleep",
  "entry.channelTags": "tags",
  "entry.moodQuestion": "How does today feel? Optional — one tap is enough.",
  "entry.moodCheckInA11y": "Mood check-in",
  "entry.moodOptionA11y": "Mood: {label}",
  "entry.energyQuestion": "And your energy? Optional.",
  "entry.energyCheckInA11y": "Energy check-in",
  "entry.energyOptionA11y": "Energy: {label}",
  "entry.sleepQuestion": "How did you sleep? Optional.",
  "entry.sleepA11y": "Sleep quality",
  "entry.sleepOptionA11y": "Sleep: {label}",
  "entry.tagsQuestion": "What shaped today? Optional — tap any.",
  "entry.tagsA11y": "Day tags",
  "entry.tagA11y": "Tag: {tag}",
  "entry.save": "Save entry",
  "entry.saved": "Saved ✓",
  "entry.savedOffline": "Saved — will sync when online",
  "entry.tooLongTitle": "Entry too long",
  "entry.tooLongBody": "Entries are limited to {max} characters.",
  "entry.sessionDamagedBody": "Account id missing — please sign in again. Your entry is still on screen.",
  "entry.crisisAlertTitle": "Support is available",
  "entry.crisisAlertBody":
    "Some of what you wrote sounds like a really heavy moment. Whatever you are carrying, you do not have to carry it alone — free, confidential help is one tap away.",
  "entry.crisisViewResources": "View support resources",
  "entry.sessionExpiredBody": "Please unlock again — your entry will still be here.",
  "entry.notAcceptedTitle": "Entry not accepted",
  "entry.notAcceptedBody": "The server couldn't store this entry as-is. Your entry is still on screen.",
  "entry.queueFullTitle": "Offline storage full",
  "entry.queueFullBody":
    "Your oldest unsynced entries are protected — connect and sync before writing more. This entry is still on screen.",
  "entry.queueAbandonedTitle": "Not saved",
  "entry.queueAbandonedBody":
    "The offline queue was cleared while saving (were you signed out?). Your entry is still on screen.",
  "entry.couldNotSaveTitle": "Could not save",

  // ------------------------------------- check-in vocabulary (audit fix 21)
  // Display labels keyed by option VALUE; the wire values themselves —
  // the numbers and the English tag tokens in src/mood.ts — never
  // localize (the server's engine reads them).
  "mood.option.heavy": "Heavy",
  "mood.option.low": "Low",
  "mood.option.okay": "Okay",
  "mood.option.good": "Good",
  "mood.option.light": "Light",
  "energy.option.drained": "Drained",
  "energy.option.steady": "Steady",
  "energy.option.energized": "Energized",
  "sleep.option.1": "Rough",
  "sleep.option.2": "Poor",
  "sleep.option.3": "Okay",
  "sleep.option.4": "Good",
  "sleep.option.5": "Rested",
  "activityTag.work": "work",
  "activityTag.family": "family",
  "activityTag.friends": "friends",
  "activityTag.exercise": "exercise",
  "activityTag.outdoors": "outdoors",
  "activityTag.rest": "rest",
  "activityTag.creative": "creative",
  "activityTag.health": "health",
  "activityTag.money": "money",
  "activityTag.travel": "travel",

  // -------------------------------------- reminder notifications (fix 22)
  // The OS-level copy (notification body, Android channel name) resolves
  // through the catalog so a Spanish device reads a Spanish nudge.
  "notify.reminderBody": "A quiet moment to write, whenever it suits you.",
  "notify.channelName": "Journal reminders",
  // The MBC check-in nudge (2026-09-27): an invitation, never a debt — no
  // "overdue", no streak, nothing to feel bad about (the same safe-messaging
  // contract as the daily reminder body).
  "notify.measureReminderBody": "A quiet moment for a wellbeing check-in, whenever it suits you.",

  // ---------------------------------------------------------------- history
  "history.snapshotReload": "Your journal changed while older entries were loading. Reloading the latest history from the start.",
  "history.revisionConflict": "Your journal changed while it was loading. Try again to reload the latest history.",
  "history.entryDeleted": "Entry deleted",
  "history.entryWord": "entry",
  "history.entryWordPlural": "entries",
  "history.loadOlderFailedTitle": "Could not load older entries",
  "history.needsConnectionTitle": "Needs a connection",
  "history.deleteOfflineBody": "Deleting removes the entry from the server, so it can't run offline. Connect and try again — nothing was changed.",
  "history.couldNotDeleteTitle": "Could not delete",
  "history.deleteConfirmTitle": "Delete this entry?",
  "history.deleteConfirmBody": "This removes the entry from your journal on every device. This can't be undone.",
  "history.finalConfirmBody": "Deleting is permanent — there is no copy anywhere to restore from.",
  "history.sessionDamagedBody": "Account id missing — please sign in again. Your text is still on screen.",
  "history.tooLongTitle": "Entry too long",
  "history.tooLongBody": "Entries are limited to {max} characters.",
  "history.updateOfflineBody": "Updating needs a connection. Your original entry and this text are both still safe; try again when connected.",
  "history.couldNotUpdateTitle": "Could not update",
  "history.updateFailedBody": "{reason} Your original entry is unchanged and this text is still on screen.",
  "history.updated": "Updated ✓",
  "history.editA11y": "Edit entry",
  "history.charCount": "{current} / {max}",
  "history.saveChanges": "Save changes",
  "history.editThisEntry": "Edit this entry",
  "history.deleteThisEntry": "Delete this entry",
  "history.backToHistory": "Back to history",
  "history.tryAgainA11y": "Try loading your history again",
  "history.offlineBody": "Your journal history loads when you're online; today's writing always works offline.",
  "history.emptyBody": "No entries yet. What you write each day will gather here — decrypted only on this device.",
  "history.searchPlaceholder": "Search your entries",
  "history.moodBadgeA11y": "Mood: {label}",
  "history.matchOne": "{count} entry match",
  "history.matchMany": "{count} entries match",
  "history.filterDay": " · {date}",
  "history.filterSearch": " · search",
  "history.filterLoaded": " · loaded history only",
  "history.entryA11y": "Entry from {date}",
  "history.showOlder": "Show older entries ({count} more)",
  "history.loadingOlder": "Loading older entries…",
  "history.loadOlder": "Load older entries",
  "history.loadOlderA11y": "Load older encrypted journal entries",
  "history.limitReached": "The newest {rows} entries are loaded. To read anything older, browse to that month on the calendar — each month loads on demand.",
  "history.monthLoaded": "{count} entries from that month are now in your history.",
  "history.monthEmpty": "No entries in that month.",
  "history.monthLoadFailed": "Could not load that month — check your connection and try again.",
  "history.noMatchSearch": "Nothing matches that search.",
  "history.noMatchDay": "Nothing matches that day.",
  "history.unreadableOne": "{count} entry couldn't be read on this device.",
  "history.unreadableMany": "{count} entries couldn't be read on this device.",
  "history.rekeyedElsewhere": "Every entry failed to decrypt — your journal was re-encrypted after a password change on another device. Sign out and sign back in with your new password.",
  "history.conflictTitle": "This entry changed on another device",
  "history.conflictBody": "Their saved version:\n{theirs}\n\nYour version:\n{yours}\n\nOverwrite their version with yours?",
  // 2026-09-26 audit M-M3: both sides of the conflict dialog are snippeted
  // to ~300 chars; the suffix states the FULL length so the truncation is
  // explicit before the destructive Overwrite choice.
  "history.conflictSnippetSuffix": "… ({count} characters total)",
  "history.conflictKeepTheirs": "Keep theirs",
  "history.conflictOverwrite": "Overwrite with mine",
  "history.deletedElsewhereTitle": "Deleted on another device",
  "history.deletedElsewhereBody": "This entry was deleted from another device, so your edit was not saved.",
  // Audit 2026-09-28 (MEDIUM): hardware back / Cancel with unsaved edits
  // confirms the discard instead of discarding silently.
  "history.discardEditTitle": "Discard your changes?",
  "history.discardEditBody": "The edits you made to this entry have not been saved.",
  "history.discardEditConfirm": "Discard changes",
  "history.discardEditCancel": "Keep editing",

  // --------------------------------------------------------------- insights
  "insights.tryAgainA11y": "Try loading your patterns again",
  "insights.baselineTitle": "Keep writing — {count} {unit} to your patterns",
  "insights.baselineBody":
    "The wait is deliberate: with less than {days} days of entries, any \"insight\" would be a guess dressed up as a finding. Real patterns need real history.",
  "insights.moodMonthDevice": "Your mood, this month (stays on this device):",
  "insights.nothingSolidTitle": "Nothing solid yet",
  "insights.allMutedBody": "Every current pattern is muted — unmute one below, or keep writing.",
  "insights.noEvidenceBody": "No recurring pattern has enough evidence. Keep writing.",
  "insights.moodMonth": "Your mood, this month",
  "insights.moodMonthNote": "Recorded on this device with your daily check-in.",
  "insights.mutedNote": "Muted — hidden here now, and out of your questions after their next update.",
  "insights.unmutedNote": "Unmuted — it returns with your next question update.",
  "insights.sensitiveBody": "A difficult thought has been returning across different days.",
  "insights.supportResources": "Support resources",
  "insights.supportResourcesA11y": "Support resources — crisis help",
  "insights.newFlag": " · new",
  "insights.meta": "{count} mentions · observation strength {density}%",
  "insights.hideEvidence": "Hide the evidence",
  "insights.whySeeing": "Why am I seeing this?",
  "insights.whySeeingA11y": "Why am I seeing this? Evidence for this pattern",
  "insights.muteA11y": "Mute this pattern — {label}",
  "insights.muteLabel": "Not about me anymore — mute",
  "insights.hideTech": "Hide technical details",
  "insights.techDetails": "Technical details",
  "insights.techDetailsA11y": "Technical details — the raw statistics",
  "insights.evidenceFootnote1": "Patterns like this can occasionally appear by chance — that's why we show the evidence.",
  "insights.evidenceFootnote2": "An observation about your own data — not a diagnosis or advice.",
  "insights.showMutedA11y": "Show muted patterns, {count} of them",
  "insights.hideMutedA11y": "Hide muted patterns",
  "insights.mutedCountHide": "Hide muted ({count})",
  "insights.mutedCountShow": "Show muted ({count})",
  "insights.mutedNoteBody": "Muted patterns stay out of your questions. Unmuting brings them back.",
  "insights.unmute": "Unmute",
  "insights.unmuteA11y": "Unmute this pattern — {label}",
  "insights.footnote": "These are observations, not advice or diagnosis. You decide what they mean.",
  "insights.unknownPhase": "server reported an unknown insights phase",
  "insights.state.emerging": "early evidence",
  "insights.state.confirmed": "seen consistently",
  "insights.state.fading": "fading",
  "insights.state.observed": "observed",
  "insights.kind.temporal": "TIMING",
  "insights.kind.mood_correlation": "MOOD LINK",
  "insights.kind.link": "DAY-AFTER LINK",
  "insights.kind.inertia": "CARRYOVER",
  "insights.kind.energy_inertia": "ENERGY CARRYOVER",
  "insights.kind.pa_inertia": "POSITIVE CARRYOVER",
  "insights.kind.na_inertia": "NEGATIVE CARRYOVER",
  "insights.kind.energy_mood_coupling": "ENERGY AND MOOD",
  "insights.kind.instability": "SWINGS",
  "insights.kind.recurring_phrase": "REPEATED PHRASE",
  "insights.kind.rumination": "REPEATED WORRY",
  "insights.kind.topic": "THEME",
  "insights.kind.mood_shift": "MOOD TREND",
  "insights.kind.avoidance": "SILENCE AFTER",
  "insights.kind.cadence": "RHYTHM",
  "insights.kind.sense_making": "SENSE-MAKING",
  "insights.kind.activity_diversity": "ACTIVITY VARIETY",
  "insights.kind.fallback": "PATTERN",
  "insights.languageTitle": "About your journal's language",
  "insights.languageBody": "Pattern analysis runs in English and Spanish. In another language your entries and check-ins still save and sync \u2014 the engine steps aside rather than guess. Language support grows with each carefully built lexicon.",
  "insights.effect.verySmall": "a very small difference",
  "insights.effect.small": "a small difference",
  "insights.effect.medium": "a medium-sized difference",
  "insights.effect.large": "a large difference",
  "insights.words.higher": "higher",
  "insights.words.lower": "lower",
  "insights.theme.work": "work",
  "insights.theme.sleep": "sleep",
  "insights.theme.social": "social life",
  "insights.theme.family": "family",
  "insights.theme.health": "health",
  "insights.theme.money": "money",
  "insights.theme.study": "study",
  "insights.theme.food": "food",
  "insights.theme.weather": "weather",
  "insights.words.narrowed": "narrowed",
  "insights.words.widened": "widened",
  "insights.method.temporal":
    "Weekday concentration tested against your own writing schedule (exact binomial, corrected for multiple comparisons).",
  "insights.method.mood_correlation":
    "Within-person: days with this theme vs your own mood baseline in the same weeks (Welch's t + effect-size gate).",
  "insights.method.link":
    "Day-after association vs your own baseline — the shape of the best-replicated daily-diary link (e.g. sleep → next-day mood).",
  "insights.method.inertia":
    "Day-to-day mood carryover (autocorrelation) compared with your own earlier norm — a dynamic tied to wellbeing in meta-analyses.",
  "insights.method.energy_inertia":
    "Day-to-day energy carryover (autocorrelation) from your own optional energy picks, compared with your own earlier norm.",
  "insights.method.pa_inertia":
    "Day-to-day carryover of your writing's POSITIVE feeling words, compared with your own earlier norm (positive and negative affect are separable streams).",
  "insights.method.na_inertia":
    "Day-to-day carryover of your writing's NEGATIVE feeling words, compared with your own earlier norm (positive and negative affect are separable streams).",
  "insights.method.energy_mood_coupling":
    "How closely your energy picks and your entry mood move together (within-person), compared with your own earlier norm.",
  "insights.method.sense_making":
    "The share of causal and insight words ('because', 'realize') in your entries, compared with your own earlier norm — a shift tied to meaning-making in the expressive-writing literature.",
  "insights.method.activity_diversity":
    "The variety of your activity tags per week (Shannon entropy), compared with your own earlier weeks.",
  "insights.method.instability": "The spread of your daily mood compared with your own earlier norm.",
  "insights.method.mood_shift": "A control chart over your daily mood vs your personal baseline — built for exactly this use.",
  "insights.method.recurring_phrase": "Near-duplicate sentence clustering across separated days.",
  "insights.method.rumination":
    "A returning negative thought. Repetitive negative thinking is a well-studied pattern; this clusters near-identical negative sentences.",
  "insights.method.topic":
    "A recurring theme discovered from your own words — not from any fixed list. Rising topics are tested against your own earlier entries (exact binomial).",
  "insights.method.avoidance":
    "Days with this theme are more often followed by a silent day than your own usual pattern (exact binomial against your base rate, corrected for multiple comparisons).",
  "insights.method.cadence":
    "The regularity of your writing rhythm compared with your own earlier norm (spread of gaps between writing days).",
  "insights.ev.window": "Evidence window",
  "insights.ev.windowValue": "{from} → {to}",
  "insights.ev.basedOn": "Based on",
  "insights.ev.basedOnValue": "{count} entries in your analysis window",
  "insights.ev.concentration": "Concentration",
  "insights.ev.concentrationValue": "{share}% of these mentions fell on {day}s — your baseline for {day}s is {baseline}",
  "insights.ev.unavailable": "unavailable",
  "insights.ev.moodDiff": "Mood difference",
  "insights.ev.moodDiffValue": "entries read {direction} by {amount} than your own norm",
  "insights.ev.size": "Size of the difference",
  "insights.ev.dayAfter": "Day-after",
  "insights.ev.dayAfterValue": "~{lag} day later — seen on {after} such days vs {other} others",
  "insights.ev.carryover": "Carryover",
  "insights.ev.carryoverMood": "mood has been carrying over more strongly than it used to for you",
  "insights.ev.carryoverEnergy": "your energy has been carrying over more strongly than it used to for you",
  "insights.ev.carryoverPositive": "your positive feelings have been carrying over more strongly than it used to for you",
  "insights.ev.carryoverNegative": "your negative feelings have been carrying over more strongly than it used to for you",
  "insights.ev.tracking": "Tracking together",
  "insights.ev.trackingValue": "your energy and your mood have been moving more in step than they used to",
  "insights.ev.senseWords": "Sense-making words",
  "insights.ev.senseWordsValue": "{recent} per 100 words lately, versus your earlier {earlier}",
  "insights.ev.activityVariety": "Activity variety",
  "insights.ev.activityVarietyValue": "{direction} — {recent} bits per week lately, versus your earlier {earlier}",
  "insights.ev.swings": "Swings",
  "insights.ev.swingsValue": "your daily mood has been spread over a wider range than it used to",
  "insights.ev.share": "Share of entries",
  "insights.ev.shareValue": "{share}% ({entries} entries, {mentions} mentions)",
  "insights.ev.earlierRecent": "Earlier → recent",
  "insights.ev.earlierRecentValue": "{earlier}% → {recent}%",
  "insights.ev.returning": "Returning for",
  "insights.ev.returningValue": "seen on {days} distinct days across {span} days",
  "insights.ev.tone": "Tone",
  "insights.ev.toneValue": "the thought reads negative",
  "insights.ev.shift": "Shift",
  "insights.ev.shiftValue": "{sign}{amount} against your baseline of {baseline}",
  "insights.ev.silentDays": "Silent days after",
  "insights.ev.silentDaysValue": "{silences} of {observed} such days (your usual silent-day rate is {rate})",
  "insights.ev.rhythm": "Rhythm",
  "insights.ev.rhythmValue": "gap spread {recent} vs your earlier {earlier} days",
  "insights.ev.method": "Method",
  "insights.tech.significance": "Significance",
  "insights.tech.significanceValue": "p = {value} (corrected for running many tests)",
  "insights.tech.cohensD": "Cohen's d",
  "insights.tech.negativity": "Negativity score",
  "insights.tech.absolutist": "Absolutist-word density",
  "insights.tech.absolutistValue": "{value} per 100 words",
  "insights.tech.carryover": "Carryover, recent vs earlier",
  "insights.tech.coupling": "Coupling, recent vs earlier",
  "insights.tech.spread": "Spread, recent vs earlier",
  "insights.tech.pairValue": "{recent} vs {earlier}",
  "insights.desc.temporal": "You've mentioned '{label}' {count} times, most often on {day}s.",
  "insights.desc.sameDay": "the same day",
  "insights.desc.certainDay": "certain day",
  "insights.desc.moodCorrelation": "Your entries read {direction} on days when '{label}' comes up (mood shift of {shift}).",
  "insights.desc.link": "The day after '{label}' comes up, your entries read {direction} than usual for you.",
  "insights.desc.inertia": "Your mood has been carrying over from day to day more than usual for you.",
  "insights.desc.energyInertia": "Your energy has been carrying over from day to day more than usual for you.",
  "insights.desc.paInertia": "Your positive feelings have been carrying over from day to day more than usual for you.",
  "insights.desc.naInertia": "Your negative feelings have been carrying over from day to day more than usual for you.",
  "insights.desc.coupling": "Your energy and your mood have been moving together more closely than usual for you.",
  "insights.desc.senseMaking": "Your writing has leaned more on sense-making words — like 'because' and 'realize' — than it used to.",
  "insights.desc.activityNarrowed": "The variety in your tagged activities has narrowed compared with your own usual.",
  "insights.desc.activityWidened": "The variety in your tagged activities has widened compared with your own usual.",
  "insights.desc.instability": "Your daily mood has swung more widely than usual for you these past weeks.",
  "insights.desc.recurringPhrase": "The phrase \"{label}\" keeps returning — {count} times so far.",
  "insights.desc.rumination": "The thought \"{label}\" keeps returning across different days — {count} times so far.",
  "insights.desc.topicRising": "'{label}' has been taking up more space in your writing lately{share}.",
  "insights.desc.topicSteady": "'{label}' is a steady presence in your writing{share}.",
  "insights.desc.topicShare": " ({share}% of entries)",
  "insights.desc.moodShift": "Your entries have read {direction} than your usual baseline lately (a shift of {shift}).",
  "insights.desc.unavailable": "Details for this observation are unavailable. Refresh your observations to see the evidence.",
  "insights.desc.noDifference": "No difference was measured in this observation.",
  "insights.desc.sleepLink": "The day after a night you rated as rougher than your own usual, your entries read {direction} than usual for you.",
  "insights.desc.sleepCorrelation": "On nights you rated as rougher than your own usual, your entries read {direction} the same day.",
  "insights.desc.sleepTemporal": "Your rougher nights (by your own ratings) fall most often on {day}s.",
  "insights.desc.avoidance": "The day after '{label}' comes up, you tend not to write{share}.",
  "insights.desc.avoidanceShare": " ({share}% of such days)",
  "insights.desc.cadence": "Your writing rhythm has been less regular than it used to be for you — longer stretches of silence between writing days.",
  "insights.desc.tagCorrelation": "Your entries read {direction} on days you tag '{label}'.",
  "insights.desc.tagLink": "The day after you tag '{label}', your entries read {direction} than usual for you.",
  "insights.desc.tagTemporal": "You tag '{label}' most often on {day}s.",
  "insights.desc.fallback": "'{label}' appeared {count} times.",
  "insights.spark.summary": "Mood trend: {trend} over {count} {unit}, latest {latest}",
  "insights.spark.steady": "steady",
  "insights.spark.rising": "rising",
  "insights.spark.falling": "falling",
  "insights.spark.positive": "positive",
  "insights.spark.negative": "negative",
  "insights.spark.neutral": "neutral",

  // --------------------------------------------------------------- question
  "question.loadFailedTitle": "Could not load question",
  "question.sessionMismatch": "session and unlocked keys do not match — sign in again",
  "question.noticedMore": "Noted — questions like this will come up more often.",
  "question.noticedLess": "Noted — this one will step back.",
  "question.feedbackSaveFailed": "Your answer stays on this device; it could not be saved just now.",
  "question.noEvidenceYet": "No recurring pattern has enough evidence yet — keep writing.",
  "question.keyShipTitle": "Your key, briefly",
  "question.keyShipBody":
    "To compute your patterns, your encryption key is sent to the server once — held in memory for up to 5 minutes, then destroyed. It is never stored, and it is only ever sent when you ask from this screen.",
  "question.today": "Today",
  "question.baselineCaption": "For now, one question a day. After {days} days of writing, your questions start coming from YOUR patterns.",
  "question.dayOf": "Day {active} of {total}",
  "question.writeAbout": "Write about this",
  "question.writeAboutA11y": "Write about this question",
  "question.oneADay": "One question a day. No advice — just something to sit with.",
  "question.resonated": "This resonated",
  "question.resonatedA11y": "This question resonated with me",
  "question.notMe": "Not me",
  "question.notMeA11y": "This question does not land for me",
  "question.refresh": "Refresh",
  "question.showToday": "Show today's question",
  "question.captionBaseline": "Today's question comes from a small built-in set — nothing leaves this device for it.",
  // 2026-09-20 audit L-57: status-0 is "no response" (offline, timeout,
  // local refusal) — the phase is UNKNOWABLE, so never caption it as the
  // baseline program; say what is actually true instead.
  "question.captionOffline": "Can't reach the server right now — here is a general question for today.",
  "question.captionInsight": "Computing your question can send your encryption key to the server once — held in memory for up to 5 minutes, never stored.",
  "question.accountMissingPlain": "Account id missing — please sign in again.",

  // --------------------------------------------------------------- settings
  "settings.reminderMorning": "Morning 9:00",
  "settings.reminderMidday": "Midday 12:00",
  "settings.reminderEvening": "Evening 20:00",
  "settings.invalidUrlTitle": "Invalid URL",
  "settings.invalidUrlBody": "Enter a full URL like https://your-server:8000",
  "settings.couldNotSaveServerTitle": "Could not save server",
  "settings.serverSavedTitle": "Saved",
  "settings.serverSavedBody": "Server URL updated. Changing server origins signs this device out to protect your session.",
  "settings.signInRequiredTitle": "Sign in required",
  "settings.signInRequiredBody": "Sign in again before retrying saved entries.",
  "settings.recoveredTitle": "Recovered entries",
  "settings.recoveredMoved": "{count} {unit} moved back into the sync queue — {rest}",
  "settings.recoveredUploadNext": "they upload on the next sync.",
  "settings.recoveredStillWaiting": "{count} still waiting.",
  "settings.recoveredNone": "Nothing could be moved yet — the entries stay safely stored on this device.",
  "settings.couldNotRetryTitle": "Could not retry",
  "settings.couldNotRetryBody": "The saved entries are still safe on this device.",
  "settings.deletedTitle": "Deleted",
  "settings.deletedBody":
    "Your account and data were deleted from the server. If anything failed to clear on this device, reinstalling the app removes the remnants.",
  "settings.deleteFailedTitle": "Delete failed",
  "settings.deleteFailedSession": "Session expired — please unlock again. Nothing was deleted.",
  "settings.exportTitle": "Export unavailable in this build",
  "settings.exportBody":
    "To protect large journals, this app needs its verified secure file-export component before it can create an export. Your entries remain safely on the server and this device.",
  "settings.reminderSaveFailedTitle": "Could not save",
  "settings.reminderSaveFailedBody": "The reminder preference wasn't saved — try again.",
  "settings.reminderNotScheduledTitle": "Reminder not scheduled",
  "settings.reminderNotScheduledBody": "Notifications are turned off for this app in your device settings — the reminder will start once they're allowed.",
  "settings.healthMirrorSaveFailedTitle": "Could not save",
  "settings.healthMirrorSaveFailedBody": "The Health preference wasn't saved — try again.",
  "settings.healthMirrorDeniedTitle": "Health access not granted",
  "settings.healthMirrorDeniedBody":
    "The Health app hasn't granted write access. You can change that in the Health app's privacy settings; the preference stays saved and nothing else changes.",
  "settings.bioOffFailedTitle": "Could not turn off",
  "settings.bioOffFailedBody": "Try again — your password keeps working either way.",
  "settings.bioTitle": "Use biometric unlock?",
  "settings.bioBody":
    "Your data key will be stored on this device, wrapped under your fingerprint or face. Your password keeps working exactly as before, and turning this off removes the stored key.",
  "settings.bioEnable": "Enable",
  "settings.bioOnFailedTitle": "Could not turn on",
  "settings.bioOnFailedBody": "Nothing was stored — your password keeps working.",
  "settings.deleteAllTitle": "Delete everything?",
  "settings.deleteAllBody":
    "All entries, patterns and your account will be permanently deleted from the server. Your local encrypted queue is also wiped. This cannot be undone. You will be asked for your password.",
  "settings.deleteAllFinalBody": "Deleting is irreversible. You will be asked for your password next.",
  "settings.continueToPassword": "Continue to password",
  "settings.rejectedOne": "{count} entry couldn't sync and was kept safely on this device.",
  "settings.rejectedMany": "{count} entries couldn't sync and were kept safely on this device.",
  "settings.retrySync": "Try syncing them again",
  "settings.retrySyncA11y": "Try syncing the recovered entries again",
  "settings.quarantinedNote": "A damaged piece of the offline queue was set aside instead of deleted. New entries sync normally.",
  "settings.legacyTitle": "Older offline entries need recovery",
  "settings.legacyBody":
    "This update protected unsent encrypted entries from being sent to the wrong server. They remain on this device but cannot be safely assigned automatically; contact support before clearing app data.",
  "settings.llmLabel": "Third-party AI analysis",
  "settings.llmBody": "Allow sending your (decrypted) entries to an external AI service for pattern analysis. Off by default; needs your password to change.",
  "settings.llmA11y": "Allow third-party AI analysis",
  "settings.reauthDeleteTitle": "Enter your password to delete everything",
  "settings.reauthBioTitle": "Enter your password to enable biometric unlock",
  "settings.changePasswordLabel": "Change password",
  "settings.changePasswordCancel": "Close change password",
  "settings.changePasswordTitle": "Change your password",
  "settings.changePasswordBody":
    "This rotates your sign-in credential AND re-encrypts your journal under a new encryption key — the recovery step if your password or key was ever exposed. Every device signs out afterwards; active sharing grants are re-wrapped automatically.",
  // v2 copy (2026-09-26): accounts on the key envelope change the password
  // WITHOUT re-encrypting anything — the honest O(1) description.
  "settings.changePasswordTitleV2": "Change your password",
  "settings.changePasswordBodyV2":
    "This changes the password that locks your encryption key. Your journal is not re-encrypted — it stays exactly as it is, and sharing with your therapist keeps working unchanged. Every device signs out afterwards.",
  "settings.newPasswordPlaceholder": "New password (12+ characters)",
  "settings.newPasswordA11y": "New password",
  "settings.changePasswordButton": "Rotate keys and sign in again",
  "settings.changePasswordButtonV2": "Change password and sign in again",
  "settings.rotateWorking": "Rotating…",
  "settings.rotateSuccessTitle": "Password changed",
  "settings.rotateSuccessBody":
    "Your journal is now encrypted under your new password. Sign in again on this device and on any other device you use.",
  "settings.rotateSuccessBodyV2":
    "Your password now unlocks a freshly wrapped copy of your encryption key; the key itself did not change, so your journal and sharing are exactly as they were. Sign in again on this device and on any other device you use.",
  "settings.rotateFailedTitle": "Could not change password",
  "settings.rotateWrongOld": "The current password was not accepted. Nothing was changed.",
  // independent audit 2026-09-27 (P2): the offline queue is sealed under the
  // OLD data key; rotating before it drains would orphan every queued entry.
  // The rotation aborts before any server-side step with this honest copy.
  "settings.rotateQueueBlocked":
    "Entries are still waiting to upload from this device, sealed under your current password — changing it now would leave them unreadable. Save them first (keep the app open while online until the queue is empty), then try again.",
  "settings.rotateRewrapFailed":
    "These sharing grants could not be re-wrapped and must be re-paired from the therapist's pairing code: {names}",
  // --- v1 → v2 key-envelope upgrade (2026-09-26) --------------------------
  // Honest scope: nothing is re-encrypted, the data key does not change;
  // the benefit is O(1) password changes from here on. The action ships the
  // CURRENT data key to the server (inside the password-wrapped envelope),
  // so it sits behind the typed-password card.
  "settings.upgradeTitle": "Upgrade key protection",
  "settings.upgradeBody":
    "A one-time change to how your password protects your journal: today your password directly derives your encryption key, so changing it re-encrypts everything. After the upgrade a separate random key encrypts your journal and your password locks it — future password changes become instant and nothing about your stored journal changes. This needs your password and takes a moment.",
  "settings.upgradeButton": "Upgrade now",
  "settings.reauthUpgradeTitle": "Enter your password to upgrade key protection",
  "settings.upgradeSuccessTitle": "Key protection upgraded",
  "settings.upgradeSuccessBody":
    "Your journal is unchanged and still opens as before. From now on, changing your password no longer re-encrypts it.",
  "settings.upgradeAlreadyTitle": "Already upgraded",
  "settings.upgradeAlreadyBody":
    "This account already uses the newer key protection. Nothing needed to change.",
  "settings.upgradeFailedTitle": "Could not upgrade key protection",
  "settings.upgradeKeyMismatchBody":
    "The encryption key on this device does not match the data stored on the server, so nothing was changed. Lock the app and unlock it again with your current password first, then retry.",
  "settings.reauthLlmTitle": "Enter your password to {action} third-party AI analysis",
  "settings.enableWord": "enable",
  "settings.disableWord": "disable",
  "settings.recoveryTitle": "Recovery kit",
  "settings.recoveryAbsent": "No recovery kit. A forgotten password means the journal cannot be reopened.",
  "settings.recoveryActiveSince": "Recovery kit active since {date}.",
  "settings.recoveryUnknown": "Recovery-kit status unknown (offline?).",
  "settings.recoveryCreate": "Create recovery kit",
  "settings.recoveryReplace": "Replace kit key",
  "settings.recoveryRemove": "Remove kit",
  "settings.recoveryShownOnce": "Your recovery key — shown only this once",
  "settings.recoveryCopyNote": "Copy it somewhere safe OUTSIDE this device (password manager, printed paper). It is the only way back in if you forget your password.",
  "settings.recoveryConfirmSaved": "I saved the key",
  "settings.recoveryNote": "The key never leaves this device in the clear; the server stores only a verifier and a sealed copy of your journal key that only this key opens.",
  "settings.recoveryNeedsPassword": "Sign in with your password (not biometrics) to manage the recovery kit.",
  "settings.recoverySetupFailed": "The kit could not be created — check your connection and try again.",
  "settings.recoveryRemoveFailed": "The kit could not be removed — try again.",
  "settings.languageTitle": "Language",
  "settings.languageDevice": "Device default",
  "settings.languageEnglish": "English",
  "settings.languageSpanish": "Español",
  "settings.languageA11y": "App language: {choice}",
  "settings.languageNote": "Applies immediately, including to open screens.",
  "settings.appearanceLabel": "APPEARANCE",
  "settings.themeSystem": "System",
  "settings.themeDark": "Dark",
  "settings.themeLight": "Light",
  "settings.themeA11y": "Theme: {mode}",
  "settings.hapticsLabel": "Quiet haptics on taps and saves",
  "settings.hapticsA11y": "Haptics",
  "settings.reminderLabel": "DAILY REMINDER",
  "settings.reminderNote": "A gentle daily nudge — local only, nothing is sent anywhere.",
  "settings.remindMeLabel": "Remind me to write each day",
  "settings.dailyReminderA11y": "Daily reminder",
  "settings.reminderTimeA11y": "Reminder time",
  "settings.reminderTimeOptionA11y": "Reminder time: {label}",
  "settings.reminderUnavailableNote": "{reason}. The preference is saved and the nudge starts once this build links notifications.",
  // Audit 2026-09-28 (LOW): the capability seams return these KEYS; the
  // reason line resolves them through t() so it localizes.
  "settings.reasonNotifModule": "The notification module is not linked in this build",
  // --- MBC check-in reminders (2026-09-27) -------------------------------
  "settings.measureReminderLabel": "CHECK-IN REMINDERS",
  "settings.measureReminderRow": "Check-in reminders",
  "settings.measureReminderA11y": "Check-in reminders",
  "settings.measureReminderNote":
    "A gentle nudge to complete a wellbeing questionnaire when your last one is older than the interval you choose. Local only — nothing is sent anywhere.",
  "settings.measureIntervalA11y": "Check-in interval",
  "settings.measureIntervalOptionA11y": "Check-in interval: {label}",
  "settings.intervalWeeks": "{count} weeks",
  "settings.safetyPlanA11y": "Open your safety plan",
  "settings.healthMirrorLabel": "HEALTH APP",
  "settings.healthMirrorRow": "Mirror mood check-ins to the Health app",
  "settings.healthMirrorA11y": "Mirror mood check-ins to the Health app",
  "settings.healthMirrorNote":
    "When on, each explicit mood check-in is also written to the Health app on this device. Fathom never reads anything from Health. Turning this off stops future writes; what the Health app already holds stays there.",
  "settings.healthMirrorUnavailableNote": "{reason}. The preference is saved and mirroring starts once this build links the Health module.",
  "settings.reasonHealthModule": "The Health module is not linked in this build",
  "settings.reasonHealthIOS18": "Apple Health State of Mind requires iOS 18 or later",
  "settings.reasonHealthOldModule": "This build's Health module predates State of Mind support",
  "settings.biometricLabel": "BIOMETRIC UNLOCK",
  "settings.biometricRow": "Unlock with your face or fingerprint",
  "settings.biometricA11y": "Biometric unlock",
  "settings.biometricNote": "Your password always keeps working.",
  "settings.shareWithTherapist": "Share with my therapist",
  "settings.measures": "Wellbeing measures",
  "settings.measuresA11y": "Open the wellbeing measures questionnaire",
  "settings.shareWithTherapistA11y": "Share your entries and patterns with a therapist",
  "settings.sharingOffNote": "Therapist sharing is not available on this server. It stays disabled until verified clinician enrollment is configured.",
  "settings.sharingUnknownNote":
    "Can’t reach the server to confirm therapist-sharing availability — check your connection and reopen Settings. Nothing is shared in the meantime.",
  "settings.whyExport": "Why export is unavailable",
  "settings.whyExportA11y": "Why export is unavailable in this build",
  "settings.deleteAccount": "Delete my account and data",
  "settings.signOut": "Sign out",
  "settings.aboutLabel": "About",
  "settings.aboutBody":
    "Fathom {version}{server}. Everything you write is encrypted on this device before it leaves. The one exception — pattern analysis — runs in a single-use session you start yourself. No advice, no diagnosis, ever.",
  "settings.serverVersionTag": " · server {version}",
  "settings.privacyPolicy": "Privacy policy",
  "settings.privacyPolicyA11y": "Read the privacy policy",
  "settings.advancedLabel": "Advanced",
  "settings.advancedNote": "Only change this if you run your own server.",
  "settings.serverUrlPlaceholder": "https://your-server:8000",
  "settings.serverUrlA11y": "Server URL",
  "settings.saveServerUrl": "Save server URL",

  // --------------------------------------------------------- measures (M-16)
  // The whole Measures screen resolves through t(): the questionnaire is the
  // most safety-adjacent string class in the app and was hardcoded English
  // before the 2026-09-20 audit fix.
  "measures.intro":
    // 2026-09-26 audit LOW: name all three instruments — the screen has
    // offered GAD-7 and PHQ-2 since 2026-09-21, the copy still said PHQ-9 only.
    "Standard wellbeing questionnaires (PHQ-9, GAD-7 and PHQ-2), completed by you. Fathom stores the score encrypted and never interprets it — reading it is your clinician's job, and it is shared only through your existing therapist consent.",
  "measures.offlineNote":
    "Your recorded history needs a connection to load. Completing the questionnaire also needs one — nothing here works offline yet.",
  "measures.loadFailed": "Could not load your measures.",
  "measures.historyTitle": "Your recorded scores",
  "measures.emptyNote": "Nothing recorded yet.",
  "measures.stemsHeader": "Over the last 2 weeks, how often have you been bothered by:",
  "measures.item9Note": " (safety item — support is always one tap away)",
  "measures.questionA11y": "Question {index}",
  "measures.questionOptionA11y": "Question {index}: {label}",
  "measures.recordButton": "Record this check-in",
  "measures.backToSettings": "Back to settings",
  "measures.sessionDamagedTitle": "Session damaged",
  "measures.sessionDamagedBody": "Account id missing — please sign in again.",
  "measures.lockedTitle": "Locked",
  "measures.lockedBody": "Your keys are locked — unlock and try again.",
  "measures.recordedStatus": "Recorded — encrypted, as always.",
  "measures.alreadyRecorded": "Already recorded — refreshing.",
  "measures.notRecordedTitle": "Not recorded",
  "measures.recordOfflineBody": "Recording needs a connection right now. Your picks are still on screen.",
  "measures.recordFailedBody": "Could not record just now. Your picks are still on screen.",
  "measures.crisisTitle": "Support is available",
  "measures.crisisBody":
    "Some of what you marked sounds heavy. Whatever you are carrying, you do not have to carry it alone — free, confidential help is one tap away.",
  "measures.viewResources": "View support resources",
  // PHQ-9 item wording (public-domain instrument). The structural list and
  // the option VALUES live in src/phq9.ts; only display copy lives here.
  "measures.phq9.item1": "Little interest or pleasure in doing things",
  "measures.phq9.item2": "Feeling down, depressed, or hopeless",
  "measures.phq9.item3": "Trouble falling or staying asleep, or sleeping too much",
  "measures.phq9.item4": "Feeling tired or having little energy",
  "measures.phq9.item5": "Poor appetite or overeating",
  "measures.phq9.item6": "Feeling bad about yourself — or that you are a failure or have let yourself or your family down",
  "measures.phq9.item7": "Trouble concentrating on things, such as reading or watching television",
  "measures.phq9.item8": "Moving or speaking so slowly that other people could have noticed — or being so fidgety or restless that you have been moving a lot more than usual",
  "measures.phq9.item9": "Thoughts that you would be better off dead, or of hurting yourself in some way",
  "measures.phq9.option0": "Not at all",
  "measures.phq9.option1": "Several days",
  "measures.phq9.option2": "More than half the days",
  "measures.phq9.option3": "Nearly every day",
  // P3 (2026-09-21): the shared 0-3 frequency option labels — GAD-7 and
  // PHQ-2 ride the same response scale (measures.optionN).
  "measures.option0": "Not at all",
  "measures.option1": "Several days",
  "measures.option2": "More than half the days",
  "measures.option3": "Nearly every day",
  // P3 (2026-09-21): the instrument selector labels.
  "measures.select.phq9": "PHQ-9 (depression, 9 items)",
  "measures.select.gad7": "GAD-7 (anxiety, 7 items)",
  "measures.select.phq2": "PHQ-2 (brief, 2 items)",
  // GAD-7 (Spitzer et al. 2006) — same public-domain status and "over the
  // last 2 weeks" stem as the PHQ-9.
  "measures.gad7.item1": "Feeling nervous, anxious, or on edge",
  "measures.gad7.item2": "Not being able to stop or control worrying",
  "measures.gad7.item3": "Worrying too much about different things",
  "measures.gad7.item4": "Trouble relaxing",
  "measures.gad7.item5": "Being so restless that it is hard to sit still",
  "measures.gad7.item6": "Becoming easily annoyed or irritable",
  "measures.gad7.item7": "Feeling afraid, as if something awful might happen",
  // PHQ-2: the two-item depression core of the PHQ-9.
  "measures.phq2.item1": "Little interest or pleasure in doing things",
  "measures.phq2.item2": "Feeling down, depressed, or hopeless",

  // -------------------------------------------------- safety plan (2026-09-27)
  // The local, encrypted personal safety plan (Stanley-Brown-inspired
  // structure; see src/safetyPlan.ts). SAFETY-CRITICAL copy: calm, plain,
  // first-person where the field is the user's own words; numbers and URLs
  // never change per locale.
  "safetyplan.navTitle": "My safety plan",
  "safetyplan.intro":
    "A safety plan is yours: what your warning signs look like, what helps, who to reach. It stays on this device, encrypted with your key — it is never sent anywhere. It is a personal tool to lean on, not a substitute for professional help.",
  "safetyplan.field.warningSigns": "My warning signs",
  "safetyplan.hint.warningSigns": "Thoughts, feelings, situations or behaviors that tell you a hard time is starting",
  "safetyplan.field.copingStrategies": "Things I can do to cope",
  "safetyplan.hint.copingStrategies": "What has calmed or grounded you before — in your own words",
  "safetyplan.field.peoplePlaces": "People and places that help",
  "safetyplan.hint.peoplePlaces": "Names, numbers and places you can turn to",
  "safetyplan.field.askForHelp": "Who I can ask for help",
  "safetyplan.hint.askForHelp": "People you trust enough to say \u201cI need help\u201d to",
  "safetyplan.field.professionals": "Professionals and services",
  "safetyplan.hint.professionals": "Your therapist, doctor or clinic — the crisis lines below are filled in to start",
  "safetyplan.field.environmentSafer": "Making my environment safer",
  "safetyplan.hint.environmentSafer": "What you could move, lock or set aside ahead of a hard moment",
  // The professionals PREFILL for a brand-new plan: the app's built-in
  // crisis lines, verbatim from the crisis screen (numbers and URLs are
  // identical in every locale by design).
  "safetyplan.prefillProfessionals":
    "988 Suicide & Crisis Lifeline — call or text 988, or chat at 988lifeline.org/chat\nCrisis Text Line — text HOME to 741741\nEmergency (US) — call 911\nOutside the US — findahelpline.com",
  "safetyplan.save": "Save my safety plan",
  "safetyplan.saved": "Saved — encrypted, as always.",
  "safetyplan.draftRestored": "Your unsaved encrypted draft was restored. Choose Save to update your plan.",
  "safetyplan.draftInfo": "Unsaved edits are kept as an encrypted draft on this device. Save updates your plan; Discard removes the draft.",
  "safetyplan.saveFailedTitle": "Could not save",
  "safetyplan.saveFailedBody": "Your plan is still on screen exactly as you typed it — try again.",
  // Audit 2026-09-28 (MEDIUM): back with unsaved plan edits confirms the
  // discard instead of discarding silently.
  "safetyplan.discardTitle": "Discard your changes?",
  "safetyplan.discardBody": "Your safety plan changes have not been saved.",
  "safetyplan.discardConfirm": "Discard changes",
  "safetyplan.discardCancel": "Keep editing",
  "safetyplan.lockedTitle": "Locked",
  "safetyplan.lockedBody":
    "Your safety plan is encrypted with your key — unlock to read or edit it. The crisis resources stay one tap away below, as always.",

  // -------------------------------------------------------- therapist share
  "share.codeNotFoundTitle": "Code not found",
  "share.codeNotFoundBody": "Check the code with your therapist — it expires 15 minutes after they generate it.",
  "share.lookupFailedTitle": "Couldn’t look up the code",
  "share.grantTitle": "Share with {name}?",
  // Sharing disclosure v2 (audit H-14/M-25): the scope this consent records
  // now names every patient-derived class the therapist can read — journal
  // entries, patterns/insights, wellbeing measures (PHQ-9 questionnaires)
  // and the caseload summaries derived from them. Keep in sync with the
  // server's SHARING_DISCLOSURE_VERSION bump to "v2".
  "share.grantBody":
    "They will be able to read every journal entry, every pattern computed from them, your wellbeing measures (PHQ-9 questionnaires), and the summary of your account that appears on their caseload list — from their therapist portal. They cannot change or delete anything — only read, and write their own private notes.\n\nYou can stop sharing at any time; that ends their access immediately, but it cannot unread what they have already seen. You will be asked for your password.",
  "share.revokeTitle": "Stop sharing with {name}?",
  "share.revokeBody": "Their access ends immediately. They keep anything they have already read. You will be asked for your password.",
  "share.stopSharing": "Stop sharing",
  "share.noAccount": "no saved account on this device",
  "share.grantDoneTitle": "Sharing started",
  "share.grantDoneBody": "{name} can now read your entries, patterns and wellbeing measures from their portal.",
  "share.revokeDoneTitle": "Sharing stopped",
  "share.revokeDoneBody": "Their access has ended.",
  "share.unavailableTitle": "Therapist sharing unavailable",
  "share.unavailableBody": "This server has not enabled verified clinician sharing. No pairing code or journal data will be sent.",
  "share.unreachableTitle": "Can’t reach the server",
  "share.unreachableBody": "Sharing availability could not be confirmed — check your connection and try again. No pairing code or journal data is sent until it is.",
  "share.sharingNowLabel": "Sharing now",
  "share.notSharingNote": "You are not sharing with anyone. Your entries stay visible only to you.",
  // L-66: a FAILED consents load is unknown status, not "not sharing" —
  // this screen is where a revoke is verified, so false certainty is the
  // worst failure direction here.
  "share.listFailedNote":
    "Couldn’t load who you are sharing with just now — check your connection and reopen this screen before relying on this list.",
  "share.sharingSince": "Sharing since {date}",
  "share.stoppedOn": "Stopped {date}",
  // Audit 2026-09-28 (INFO): non-active consent rows with no revoked_at
  // (older servers) — the bare status instead of "Stopped " + empty date.
  "share.stopped": "Stopped",
  "share.addLabel": "Add your therapist",
  "share.addBody": "Ask your therapist for a pairing code from their portal, then enter it here. Codes expire after 15 minutes.",
  // SAS (2026-09-26): sets the expectation beside the pairing-code input —
  // after lookup, a 6-digit match code and the key fingerprint must be
  // compared with the therapist out of band before anything is shared.
  "share.sasIntro":
    "After you enter the code, this app shows a match code and a key fingerprint. Read both back to your therapist and check they match what their portal shows before you share anything.",
  "share.codePlaceholder": "e.g. 7X2KQM4N",
  "share.codeA11y": "Therapist pairing code",
  "share.lookingUp": "Looking up…",
  "share.findTherapist": "Find my therapist",
  "share.fingerprintNote":
    "Key fingerprint: {fingerprint}\nRead it back to your therapist and check it matches the one their portal shows — a mismatch means the key was substituted in transit.",
  // SAS (2026-09-26): the server-computed pairing checksum over (code, wrap
  // key, your account). A substituted key changes it; two humans comparing
  // it out of band are the detection. Rendered only when well-formed.
  "share.sasNote":
    "Match code: {sas}\nRead it back to your therapist and check it matches the one their portal shows for this pairing — a mismatch means the pairing may have been tampered with. Do not continue.",
  // C-7 (2026-09-21): the out-of-band fingerprint check is an ACTION —
  // the grant proceeds only through an explicit "fingerprints match" tap.
  "share.fingerprintsMatch": "Fingerprints match — continue",
  "share.fingerprintsDontMatch": "They don’t match",
  "share.mismatchTitle": "Do not continue",
  "share.mismatchBody":
    "If the fingerprints do not match, the pairing may have been intercepted. Contact your therapist on a channel you already trust before sharing anything.",
  "share.disclosure":
    "Sharing lets them read your journal entries, your patterns and insights, your wellbeing measures (PHQ-9 questionnaires), and your caseload-summary line (never change anything), and write their own private notes. You can stop at any time; what they already read cannot be unread.",
  "share.shareWithName": "Share with {name}",
  "share.reauthGrantTitle": "Enter your password to share with {name}",
  "share.reauthRevokeTitle": "Enter your password to stop sharing",
  // M-25: the server reports a sharing-disclosure version this app does not
  // know (either direction of drift). Calm state: no new grant is offered
  // until the versions line up, existing sharing and revoking stay intact.
  "share.termsUpdatedTitle": "Sharing terms updated",
  "share.termsUpdatedBody":
    "What a therapist can read has changed — it now includes your wellbeing measures (PHQ-9 questionnaires). Update this app, then share again to see and accept the current terms. Your existing sharing keeps working, and you can stop it below at any time.",
  // M-25: the server rejected a grant because the disclosure reviewed on
  // this screen is no longer the current one (409 disclosure_outdated).
  // Nothing was shared — the honest next step is to start again.
  "share.grantOutdatedTitle": "Sharing terms updated",
  "share.grantOutdatedBody":
    "The sharing terms changed before this was sent, so nothing was shared. Nothing about you changed on the server. Start again to review the current terms — they now include your wellbeing measures (PHQ-9 questionnaires).",
  // --- voice journaling (VOICE_PLAN 2026-09-29) -----------------------------
  "entry.micRecord": "Record instead",
  "entry.micRecording": "Recording…",
  "entry.micRecordingNote": "Speak in any language — you will review the transcript before anything is saved.",
  "entry.micStop": "Stop recording",
  "entry.voiceDiscardTake": "Use text only",
  "entry.voiceTranscribing": "Transcribing your recording…",
  "entry.voiceReviewTitle": "Your recording",
  "entry.voiceLanguage": "Detected language: {lang}",
  "entry.voiceEnglishPreview": "English translation (for your therapist)",
  "entry.voiceKeepOn": "Keep the recording for 30 days — tap to turn off",
  "entry.voiceKeepOff": "The recording will be deleted when you save — tap to keep 30 days",
  "entry.voiceConsentNeeded": "Voice journaling needs your permission first — turn it on in Settings.",
  "entry.voiceUnavailable": "Voice journaling is not available on this server.",
  "entry.voiceMicDenied": "Microphone access was denied — allow it in your app settings to record.",
  "entry.voiceRecordFailed": "Recording failed — please try again.",
  "entry.voiceTranscribeFailed": "Transcription failed — please try again.",
  "entry.voiceAudioNotKept": "The entry was saved, but the recording could not be stored.",
  "entry.voiceAudioQueuedNote": "Saved offline. The recording is kept encrypted on this device and will upload when you're back online.",
  // M3: a transcript replaces typed words — confirm before they are lost.
  "entry.voiceReplaceTitle": "Record instead of typing?",
  "entry.voiceReplaceBody":
    "The transcript will replace what you have written so far. Your typed words will be lost.",
  "entry.voiceReplaceConfirm": "Record instead",
  "history.playRecording": "Play recording",
  "history.stopRecording": "Stop playback",
  "history.deleteRecording": "Delete recording",
  "history.voiceBadge": "recorded",
  // --- voice consent & sharing (VOICE_PLAN 2026-09-29, audit C5) ----------
  // Settings voice section: same copy/standing as web's Settings view.
  "settings.voiceLabel": "Voice journaling",
  "settings.voiceRow": "Allow voice journaling",
  "settings.voiceA11y": "Allow voice journaling",
  "settings.voiceNote":
    "Record entries in any language. Your recording is sent to {provider} to be transcribed and deleted immediately after; only the encrypted text is stored. Recordings you keep are stored encrypted for 30 days. Off by default; needs your password to change.",
  "settings.voiceStaleNote":
    "The server's transcription provider changed — re-enable to review and accept the new terms.",
  "settings.voiceNotOffered": "Voice journaling is not offered by this server.",
  "settings.reauthVoiceTitle": "Enter your password to {action} voice journaling",
  // Share screen: additive scope on a live therapist grant.
  "share.voiceTitle": "Let your therapist hear your recordings",
  "share.voiceOnBody":
    "Your therapist can already read your entries (and their English translation). Turning this on also lets them play the original voice recordings you keep — tone can carry what text does not. They keep this access only while sharing is active.",
  "share.voiceOffBody":
    "Your therapist will no longer be able to play the voice recordings attached to your entries. They can still read the entries themselves, and a recording they already downloaded cannot be unheard.",
  "share.voiceOn": "Therapist can hear my recordings",
  "share.voiceOff": "Therapist cannot hear my recordings",
  "share.voiceA11y": "Let {name} hear my recordings",
  "share.voiceNote":
    "Your therapist can already read your entries (and their English translation). Turning this on also lets them play the original voice recordings you keep — tone can carry what text does not. They keep this access only while sharing is active.",
  "share.reauthShareVoiceTitle": "Enter your password to change what {name} can hear",
};
