/**
 * Settings (WEB_PLAN P7.3–7.6): appearance (Light/Dark/Auto theme), LLM
 * consent (re-authenticated), the access log ("who accessed my data"),
 * the web-first ciphertext export download, queue recovery,
 * verifier-gated account deletion with the retention honesty note, and
 * the password-change flows — ROUTED BY KEY SCHEME (2026-09-26): v1
 * accounts keep the full rekey rotation (two single-use processing
 * sessions, therapist-grant re-wraps, credential rotation), v2 accounts
 * get the O(1) envelope re-wrap (PUT /account/password), and v1 accounts
 * can self-upgrade to v2 ("Upgrade key protection").
 *
 * Redesign 2026-09-26: sectioned cards (Appearance / Privacy & data /
 * Access log / Account / an isolated red Danger zone), the LLM consent
 * becomes a real switch, the theme preference is a segmented control,
 * and the access log renders as a timeline.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, auth, ApiError, sessionUsername, type ListedConsent } from "../api/client";
import { decrypt, deriveMasterKey, toBase64, fromBase64, zeroize, type Bytes } from "../crypto/core";
import { buildAad } from "../crypto/aad";
import { KDF_PARAMS_DEFAULT, rewrapDataKey, validateKdfParams, type KdfParams } from "../crypto/envelope";
import { decryptEntry } from "../crypto/patient";
import { wrapDataKeyForTherapist } from "../crypto/sharing";
import { derivePatientKeys, type PatientKeys } from "../crypto/keys";
import { rebindEntryVersions, forgetAllEntryVersions } from "../entryVersions";
import { clearActiveDraft, rewrapActiveDraft } from "../entryDraft";
import { CADENCE_INTERVALS, clearMeasureCadence, readMeasureCadence, writeMeasureCadence, type MeasureCadencePref } from "../measureCadence";
import { clearSafetyPlan, rewrapSafetyPlan } from "../safetyPlan";
import { passwordPolicyError } from "./LoginView";
import { drainPendingQueueForRotation, requeueRejected, rejectedEntries, queueLength, clearQueue, rewrapQueue } from "../offlineQueue";
import { broadcastTabLockdown } from "../tabLockdown";
import { downloadTextFile, localStore, randomBytes } from "../platform";
import { clearMoodLog, rewrapMoodLog } from "../moodLog";
import { clearFeedback, rewrapFeedback } from "../questionFeedback";
import { clearPendingMeasure, rewrapPendingMeasure } from "../pendingMeasure";
import { clearMutedPids, readMutedPids, writeMutedPids } from "../patternMutes";
import { forgetAnalysisGeneration } from "../stateSeqGuard";
import { applyLanguagePref, getLanguagePref, t, type LanguagePref } from "../strings";
import { vault } from "../vault";
import { applyThemePref, readThemePref, writeThemePref, type ThemePref } from "../theme";
import { Button, Card, ErrorBanner, Field, Note, PillNote, SegmentedControl, Toggle } from "../ui";

/** Resume-ladder step (H-4/M-W2, audit 2026-09-26 — port of mobile
 *  rotation.ts newKeyReadsJournal): can the CANDIDATE new key decrypt at
 *  least one live blob? Proves a rekey_key_mismatch means "already
 *  rekeyed by an earlier attempt with THIS password" rather than "wrong
 *  key", so the flow may continue from the rewrap stage.
 *
 *  2026-09-26 audit follow-up B-2: the rekey also moves MEASURES and
 *  insights, so an EMPTY journal must not trivially verify — a user with
 *  a PHQ-9 history but zero entries would otherwise "verify", complete
 *  the credential rotation, and silently orphan every stored measure
 *  under the attempt-1 key. An empty journal probes one measure row
 *  instead; both empty trivially verifies (nothing to mismatch). */
async function newKeyReadsJournal(userId: string, newDataKey: Bytes): Promise<boolean> {
  try {
    const page = await api.listEntriesPage({ limit: 1, offset: 0 });
    if (page.entries.length > 0) {
      const entry = page.entries[0]!;
      if (typeof entry.blob !== "string") return false;
      try {
        await decryptEntry(newDataKey, userId, entry.client_entry_id, entry.blob, entry.content_version ?? undefined);
        return true;
      } catch {
        return false;
      }
    }
    const measures = await api.listMeasuresPage({ offset: 0 });
    if (measures.measures.length === 0) return true;
    const row = measures.measures[0]!;
    if (typeof row.blob !== "string" || typeof row.client_measure_id !== "string") return false;
    try {
      await decrypt(newDataKey, fromBase64(row.blob), buildAad("measure", userId, row.client_measure_id));
      return true;
    } catch {
      return false;
    }
  } catch {
    // The probe itself failed (offline/5xx): unverifiable, so not "readable".
    return false;
  }
}

/** 2026-09-26 audit follow-up B-1: the pending rotation salt, persisted
 *  LOCALLY before the rekey attempt and cleared only on full completion.
 *  The first M-W2 cut drew a fresh random salt per attempt, so a retry
 *  after a post-rekey failure derived DIFFERENT keys — the resume ladder
 *  could never verify and the user dead-ended at "repeat the password
 *  change to finish it", an instruction that always failed. Reusing the
 *  pending salt makes the retry derive the same keys as the attempt that
 *  rekeyed the corpus, so the ladder actually fires. The salt is public
 *  material (the server stores it in the clear after rotation); it is
 *  inert without the password and is wiped by deletion's mindpattern.*
 *  prefix sweep. (v1 flow only — the v2 O(1) change never rekeys, so it
 *  never needs a resume ladder.) */
const pendingSaltKey = (userId: string): string => `mindpattern.rotatePendingSalt.${userId}`;

export function SettingsView(props: { onLockdown: (notice: string) => void; onOpenSafetyPlan?: () => void }): React.JSX.Element {
  const [themePref, setThemePref] = useState<ThemePref>(() => readThemePref());
  // Language (audit 2026-09-26 LOW): 'auto' | 'en' | 'es', applied live.
  const [languagePref, setLanguagePref] = useState<LanguagePref>(() => getLanguagePref());
  // The opt-in check-in cadence (clinical review 2026-09-27): null = not
  // yet read from the per-account slot; the interval control renders only
  // while the reminder is on.
  const [cadence, setCadence] = useState<MeasureCadencePref | null>(null);
  const [llm, setLlm] = useState<{ available: boolean; enabled: boolean } | null>(null);
  // 2026-09-26 audit LOW b: a FAILED meta/consent read is an explicit
  // unknown state with a retry — the LLM section used to vanish silently.
  const [llmLoad, setLlmLoad] = useState<"loading" | "known" | "unknown">("loading");
  const [accessRows, setAccessRows] = useState<{ at: string; action: string; actor: string }[] | null>(null);
  const [accessCursor, setAccessCursor] = useState<string | null>(null);
  // 2026-09-28 audit (INFO): a failed page-2 fetch surfaces here instead
  // of wiping the rows already on screen.
  const [accessError, setAccessError] = useState("");
  const [queued, setQueued] = useState<number | null>(null);
  const [rejected, setRejected] = useState<number>(0);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [deleteText, setDeleteText] = useState("");
  /** The account's key scheme (2026-09-26): routes the password-change
   *  card between the v1 rekey flow and the v2 O(1) re-wrap, and gates
   *  the "Upgrade key protection" action. null = not yet known; "unknown"
   *  (fetch failed) honestly blocks BOTH cards instead of guessing — the
   *  v1 flow against a v2 account 409s key_scheme_conflict, and silently
   *  showing v2 copy to a v1 account would promise re-encryption that
   *  does not happen. A 404 means the backend predates the endpoint and
   *  therefore has no v2 accounts at all: v1. */
  const [keyScheme, setKeyScheme] = useState<"v1" | "v2" | null>(null);
  const [schemeUnknown, setSchemeUnknown] = useState(false);
  const [upgradePassword, setUpgradePassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const generation = useRef(0);

  /** The account's CURRENT validated kdf_params as the mount-time envelope
   *  read reported them (2026-09-28 audit): null for v1 accounts (the
   *  upgrade card's only audience) and any backend that predates params —
   *  those keep the pinned 600k default. A v2 account's declared params
   *  ride here so the flows below never re-wrap under params the stored
   *  AAD does not declare. */
  const envelopeParams = useRef<KdfParams | null>(null);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    if (!vault.isUnlocked()) return;
    setSchemeUnknown(false);
    setLlmLoad("loading");
    const [meta, consentState, envelope] = await Promise.all([
      api.meta().catch(() => null),
      api.getLlmConsent().catch(() => null),
      api.keyEnvelope().then(
        (body) => body,
        (err: unknown) => (err instanceof ApiError && err.status === 404
          // A 404 means the backend predates the endpoint (v1-only world):
          // the full v1-shaped answer, no envelope fields.
          ? { key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null }
          : null),
      ),
    ]);
    if (generation.current !== run) return;
    if (envelope) {
      setKeyScheme(envelope.key_scheme === "v2" ? "v2" : "v1");
      setSchemeUnknown(false);
      // 2026-09-28 audit: remember the DECLARED params when they parse —
      // an invalid echo (hostile/buggy server) leaves null, which every
      // consumer below treats as the pinned default for v1-shaped state;
      // the v2 rotation re-validates FRESH at press time regardless.
      if (envelope.kdf_params == null) {
        envelopeParams.current = null;
      } else {
        try {
          envelopeParams.current = validateKdfParams(envelope.kdf_params);
        } catch {
          envelopeParams.current = null;
        }
      }
    } else {
      setKeyScheme(null);
      setSchemeUnknown(true);
    }
    if (meta && consentState) {
      setLlm({ available: meta.llm_available, enabled: consentState.enabled });
      setLlmLoad("known");
    } else {
      setLlm(null);
      setLlmLoad("unknown");
    }
    const owner = vault.ownerUserId();
    if (owner) {
      setQueued(await queueLength(owner).catch(() => 0));
      setRejected((await rejectedEntries(owner).catch(() => [])).length);
      setCadence(await readMeasureCadence(owner));
    }
    await loadAccess();
  }, []);

  const loadAccess = useCallback(async (cursor?: string): Promise<void> => {
    try {
      const page = await api.accessLogPage(cursor);
      setAccessRows((current) => (cursor && current ? [...current, ...page.rows] : page.rows));
      setAccessCursor(page.nextCursor);
      setAccessError("");
    } catch {
      // 2026-09-28 audit (INFO): a page-2 failure must not WIPE the rows
      // already on screen — the fetched pages were true when fetched and
      // the next press retries the cursor. Keep them, surface the honest
      // banner; only a FRESH load failure may reset to the empty state.
      if (cursor) {
        setAccessError(t("settings.accessLoadFailedWeb"));
      } else {
        setAccessRows([]);
        setAccessCursor(null);
        setAccessError("");
      }
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const chooseTheme = (pref: string): void => {
    const next = pref === "light" || pref === "dark" ? pref : "auto";
    setThemePref(next);
    writeThemePref(next);
    applyThemePref(next);
  };

  const chooseLanguage = (pref: string): void => {
    const next: LanguagePref = pref === "en" || pref === "es" ? pref : "auto";
    setLanguagePref(next);
    // Live AND persisted: the catalog swaps in place (subscribers re-render
    // — this view included) and the next load resolves the same choice.
    applyLanguagePref(next);
  };

  /** The check-in cadence: local non-content state in the per-account
   *  slot (measureCadence.ts) — the toggle and the interval persist
   *  immediately, with no server round trip. Toggling ON keeps the
   *  already-chosen interval (4 weeks until the patient picks one). */
  const chooseCadence = (pref: MeasureCadencePref): void => {
    const owner = vault.ownerUserId();
    if (!owner) return;
    setCadence(pref);
    void writeMeasureCadence(owner, pref);
  };

  const toggleLlm = async (enabled: boolean): Promise<void> => {
    if (!vault.isUnlocked()) return;
    setBusy(true);
    setError("");
    try {
      await api.setLlmConsent(enabled, toBase64(vault.get().authKey));
      setLlm((current) => (current ? { ...current, enabled } : null));
      setStatus(enabled ? t("settings.llmEnabledNote") : t("settings.llmDisabledNote"));
    } catch (err) {
      if (err instanceof ApiError && err.code === "llm_unavailable") setError(t("settings.llmNotOfferedToggle"));
      else setError(err instanceof Error ? err.message : t("settings.llmToggleFailed"));
    } finally {
      setBusy(false);
    }
  };

  const exportData = async (): Promise<void> => {
    setBusy(true);
    setError("");
    try {
      const response = await api.exportAccountRaw();
      if (!response.ok) throw new Error(`export failed (${response.status})`);
      const bundle = await response.text();
      const ok = downloadTextFile(`mindpattern-export-${new Date().toISOString().slice(0, 10)}.json`, bundle, "application/json");
      setStatus(ok ? t("settings.exportOk") : t("settings.exportBlocked"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("settings.exportFailed"));
    } finally {
      setBusy(false);
    }
  };

  const recoverQueue = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner) return;
    setBusy(true);
    try {
      const moved = await requeueRejected(owner);
      setQueued(await queueLength(owner));
      setRejected((await rejectedEntries(owner)).length);
      setStatus(moved > 0 ? t(moved === 1 ? "settings.recoveredOne" : "settings.recoveredMany", { count: moved }) : t("settings.recoveredNone"));
    } finally {
      setBusy(false);
    }
  };

  /** The full rotation (P7.4): rekey corpus → re-wrap grants → rotate the
   *  credential (epoch death everywhere, disclosed). Ordering is the
   *  mobile rotation.ts contract: the rekey MUST land while both keys are
   *  derivable; the credential rotation MUST be last (it kills the token).
   *
   *  H-4 + M-W2 (audit 2026-09-26, port of mobile's audit-round-2 F-4):
   *  once the server has moved the corpus to the new key — this attempt's
   *  rekey OR a resumed earlier one — a live session still holding the
   *  now-dead OLD data key must never accept new writes. Any later-step
   *  failure therefore LOCKS DOWN with the honest "the server has already
   *  moved to the new key; you must unlock again" message, never a banner
   *  over live keys. The rekey_key_mismatch ladder keeps a half-finished
   *  rotation finishable, and the derived new-key generation is zeroized
   *  in finally. */
  const rotatePassword = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    // M-1 (2026-09-26 pentest): the FULL registration policy applies on the
    // rotation path too — a length-only gate here let users rotate to
    // policy-barred passwords (password1234, aaaaaaaaaaaa), silently
    // lowering the offline-guessing floor on the credential-changing path.
    // Mobile enforces the identical check (SettingsScreen.tsx).
    const policy = passwordPolicyError(newPassword);
    if (policy) {
      setError(policy);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError(t("settings.pwMismatch"));
      return;
    }
    setBusy(true);
    setError("");
    const old = vault.get();
    // H-4(c): the derived new-key generation is zeroized in finally (mobile
    // rotation.ts:251-254) — success, failure, and lockdown alike.
    let newKeys: PatientKeys | null = null;
    let serverMovedToNewKey = false;
    try {
      // independent audit 2026-09-27 (P1): the offline queue's blobs are
      // sealed under the OLD data key and were never part of the rewrap
      // family — after the server rekey they would upload and become
      // permanently undecryptable. Best-effort drain FIRST (the user is
      // necessarily online to rotate); anything that cannot leave right
      // now ABORTS before any server-side step, honestly — a rotation that
      // orphaned queued entries is the worse outcome by far.
      const remainingQueued = await drainPendingQueueForRotation(owner).catch(() => -1);
      if (remainingQueued !== 0) {
        setError(t("settings.rotateQueueBlocked"));
        return;
      }
      // B-1 (2026-09-26 audit follow-up): reuse a PENDING salt from an
      // earlier attempt that died at/after its rekey, so this retry
      // derives the same keys that already encrypted the corpus — that is
      // what makes the rekey_key_mismatch resume ladder below reachable
      // in production. A fresh draw per attempt (the first cut) could
      // never verify, dead-ending the user on "repeat the password change
      // to finish it" — an instruction that always failed.
      // M-4 (2026-09-28 audit): every OTHER signed-in tab still holds the
      // OLD data key and a live bearer — lock them down NOW, before any
      // server step, so their direct saves and reconnect flushes cannot
      // upload old-key blobs to a rekeyed corpus.
      broadcastTabLockdown("rotation");
      const pendingB64 = localStore.get(pendingSaltKey(owner));
      const newSalt = pendingB64 ? fromBase64(pendingB64) : randomBytes(16);
      const newSaltB64 = toBase64(newSalt);
      localStore.set(pendingSaltKey(owner), newSaltB64);
      newKeys = await derivePatientKeys(await deriveMasterKey(newPassword, newSalt));

      // Const alias: keeps TS's non-null narrowing inside the closures below.
      const newKey = newKeys;
      let oldB64 = "";
      for (const byte of old.dataKey) oldB64 += String.fromCharCode(byte);
      let newB64 = "";
      for (const byte of newKey.dataKey) newB64 += String.fromCharCode(byte);
      const oldSession = await api.openProcessingSession(btoa(oldB64));
      const newSession = await api.openProcessingSession(btoa(newB64));
      try {
        await api.rekeyStoredData(oldSession.session_token, newSession.session_token, toBase64(old.authKey));
        serverMovedToNewKey = true;
      } catch (err) {
        if (err instanceof ApiError && err.code === "rekey_key_mismatch") {
          // Resume ladder (mobile rotation.ts:131-152): a previous attempt
          // already moved the blobs to a new key. Continue ONLY if the key
          // we are about to make current can actually read the corpus;
          // otherwise the honest stop — never a false "NOTHING changed".
          if (!(await newKeyReadsJournal(owner, newKey.dataKey))) {
            // B-3 (2026-09-26 audit follow-up): the corpus is provably
            // under a key this vault cannot read (an earlier attempt's
            // different password, or a transient probe failure). By the
            // H-4 rule the session must NOT keep writing under the dead
            // old key — lock down with the honest "sign in with the
            // password from that earlier change" copy. A plain banner
            // over live keys was the data-loss shape H-4 exists to close.
            props.onLockdown(t("settings.rotateAlreadyRotated"));
            return;
          }
          serverMovedToNewKey = true; // idempotent completion from rewrap on
        } else {
          throw err;
        }
      }

      // Re-wrap every active grant to the therapists' CURRENT public keys
      // (the old wraps open the old data key, which is now dead).
      // B-4 (2026-09-26 audit follow-up): one grant's rewrap failing (or
      // the listing itself) must not abort the rotation — the corpus and
      // credential have already moved, so aborting here manufactured the
      // unrecoverable half-rotated state. Mobile parity (rotation.ts
      // stage 4): collect the failures, complete the flow, surface them
      // in the completion notice; the patient re-grants via pairing.
      const rewrapFailures: string[] = [];
      let consents: ListedConsent[] = [];
      try {
        consents = await api.listConsents();
      } catch {
        rewrapFailures.push("(could not list sharing grants)");
      }
      for (const consent of consents) {
        if (consent.status !== "active" || !consent.therapist_wrap_pub_key) continue;
        try {
          const wrap = await wrapDataKeyForTherapist(newKey.dataKey, consent.therapist_wrap_pub_key, owner, consent.therapist_id);
          await api.rewrapConsent(consent.id, wrap.ephemeralPubB64, wrap.wrappedKeyB64, toBase64(old.authKey));
        } catch {
          rewrapFailures.push(consent.display_name || consent.username);
        }
      }

      await api.rotateCredential(toBase64(old.authKey), newSaltB64, toBase64(newKey.authKey));
      // Full completion: the pending rotation salt has done its job.
      localStore.remove(pendingSaltKey(owner));
      await rebindEntryVersions(owner, old.dataKey, newKey.dataKey).catch(() => forgetAllEntryVersions(owner));
      // 2026-09-26 audit follow-up (B-7): the mood log, question
      // feedback, and pattern mutes are sealed under the OLD data key —
      // REWRAP each under the new key so the user's trend history and mute
      // choices survive the password change (the first cut cleared them;
      // mobile parity in kind, not in loss). Any rewrap failure falls back
      // to the old clear-on-rotate: a readable-empty store beats a store
      // sealed under a key nothing will derive again.
      await rewrapMoodLog(old.dataKey, newKey.dataKey, owner).catch(() => clearMoodLog(owner).catch(() => undefined));
      await rewrapFeedback(old.dataKey, newKey.dataKey, owner).catch(() => clearFeedback(owner).catch(() => undefined));
      // The lock-sealed journal draft rides the same family (audit
      // 2026-09-26): re-sealed under the new key, or cleared if unreadable.
      await rewrapActiveDraft(old.dataKey, newKey.dataKey, owner).catch(() => clearActiveDraft(owner).catch(() => undefined));
      // The local safety plan (clinical review 2026-09-27) rides it too —
      // durable patient-written content, so a rotation re-seals it rather
      // than losing it; an unreadable plan degrades to blank, never an
      // error that blocks the rotation.
      await rewrapSafetyPlan(old.dataKey, newKey.dataKey, owner).catch(() => clearSafetyPlan(owner).catch(() => undefined));
      // Re-audit 2026-09-27: the pending-measure slot rides the same
      // family — an in-flight questionnaire survives the rotation (or is
      // cleared if unreadable; it is disposable metadata, never worth a
      // rotation-blocking error).
      await rewrapPendingMeasure(old.dataKey, newKey.dataKey, owner).catch(() => clearPendingMeasure(owner).catch(() => undefined));
      await readMutedPids(old.dataKey, owner)
        .then((pids) => writeMutedPids(newKey.dataKey, owner, pids))
        .catch(() => clearMutedPids(owner).catch(() => undefined));
      // The offline queue rides the same family (independent audit
      // 2026-09-27, P1): anything still held locally — a rejected entry,
      // or an item another tab queued mid-rotation — is rewrapped old→new
      // under the SAME AAD, under the queue's Web Lock. A blob that cannot
      // be rewrapped stays as-is (it fails visibly on requeue); the
      // completed rotation is never blocked.
      await rewrapQueue(owner, old.dataKey, newKey.dataKey).catch(() => undefined);
      props.onLockdown(
        rewrapFailures.length > 0
          ? t("settings.rotateSuccessPartialNotice", { count: rewrapFailures.length })
          : t("settings.rotateSuccessNotice"),
      );
    } catch (err) {
      if (serverMovedToNewKey) {
        // H-4(a): the server-side corpus is ALREADY under the new key (this
        // attempt's rekey or the resumed one). The old data key in this
        // vault is dead — an entry written now would seal under a key
        // nothing can decrypt with. Lock down with the honest message.
        props.onLockdown(t("settings.rotateMovedLockdown"));
        return;
      }
      setError(err instanceof Error ? err.message : t("settings.rotateFailed"));
    } finally {
      if (newKeys) zeroize(newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
      setBusy(false);
    }
  };

  /** The O(1) v2 password change (2026-09-26): the vault's data key is the
   *  RANDOM envelope key — it never rotates, so there is no rekey, no
   *  consent re-wrap, and no local re-wrapping (mood log, drafts, mutes
   *  all stay sealed under the same key). The client derives the NEW
   *  salt + verifier, re-wraps the SAME data key under the new password,
   *  and uploads one payload; the server swaps credential + envelope in
   *  one transaction and bumps the token epoch — every session dies with
   *  the 204, so success funnels to the honest lockdown, like v1. */
  const rotatePasswordV2 = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    const username = sessionUsername();
    if (!owner || !username || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    // The same full policy as the v1 path (M-1): the envelope re-wrap is
    // the new offline-guessing floor on the credential-changing path.
    const policy = passwordPolicyError(newPassword);
    if (policy) {
      setError(policy);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError(t("settings.pwMismatch"));
      return;
    }
    setBusy(true);
    setError("");
    const old = vault.get();
    let newKeys: PatientKeys | null = null;
    let newSalt: Bytes | null = null;
    // 2026-09-28 audit (LOW, the moodLog/Entry M-3 idiom): snapshot BOTH
    // vault buffers BEFORE the awaits — vault.get()'s buffers are SHARED,
    // and a lock landing mid-flow zeroizes them, so the re-wrap and the
    // verifier below would otherwise run under all-zero bytes. The copies
    // die in the finally.
    const dataKey = new Uint8Array(new ArrayBuffer(old.dataKey.length));
    dataKey.set(old.dataKey);
    const authKey = new Uint8Array(new ArrayBuffer(old.authKey.length));
    authKey.set(old.authKey);
    try {
      // M-4 (2026-09-28 audit): lock every other signed-in tab down before
      // the credential swap kills its bearer mid-write (the v2 corpus key
      // never rotates, but a mid-flight save under a dying session is its
      // own honest-loss window).
      broadcastTabLockdown("rotation");
      // 2026-09-28 audit (MEDIUM, mobile rotation.ts parity): the re-wrap
      // KEEPS the account's CURRENT kdf_params. The server retains the
      // stored params blob when new_kdf_params is absent, so deriving and
      // wrapping under the 600k DEFAULT would desynchronize the blob from
      // the AAD and brick the next unlock of any non-default-params
      // account (the server accepts 100k-10M). The params and the KEK now
      // come from one source: the account's own envelope, fetched FRESH at
      // press time and validated. A params change is a separate future
      // action, deliberately not smuggled into a password change.
      const envelope = await api.keyEnvelope();
      const params = envelope.kdf_params == null ? KDF_PARAMS_DEFAULT : validateKdfParams(envelope.kdf_params);
      if (params.algorithm !== "pbkdf2-sha256") {
        // This build derives PBKDF2 only (no native WebCrypto Argon2):
        // refuse BEFORE any server step rather than minting an envelope
        // under params it can never reproduce. Honest, localized, no
        // partial state.
        setError(t("settings.kdfUnsupportedWeb"));
        return;
      }
      // A lock during the envelope fetch: nothing has moved yet — abort
      // honestly instead of opening a session under a dead key.
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
        return;
      }
      // M-1 (2026-09-28 audit): open a processing session with the CURRENT
      // data key FIRST — the server's possession probe authorizes the
      // envelope swap on every v2 password change (the verifier alone
      // proves the credential, not the key). Failure here surfaces the
      // honest retry error; there is no tokenless fallback.
      const processingToken = (await api.openProcessingSession(toBase64(dataKey))).session_token;
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
        return;
      }
      newSalt = randomBytes(16);
      // The KEK derives at the account's OWN iteration count (see above):
      // the params and the derivation are one decision now.
      newKeys = await derivePatientKeys(await deriveMasterKey(newPassword, newSalt, params.iterations));
      const wrappedDataKeyB64 = await rewrapDataKey(dataKey, newKeys.masterKey, newSalt, username, params);
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
        return;
      }
      await api.changePassword({
        verifierB64: toBase64(authKey),
        newSaltB64: toBase64(newSalt),
        newVerifierB64: toBase64(newKeys.authKey),
        wrappedDataKeyB64,
        // Declared EXPLICITLY equal to the account's current params — the
        // server would retain them anyway, but the body now says what the
        // bytes bind to (a tampered AAD echo cannot smuggle a change in).
        newKdfParams: params as unknown as Record<string, unknown>,
        processingToken,
      });
      // No local rewrap of anything: the data key did not change. The
      // epoch bump killed this token too — lockdown, honestly.
      props.onLockdown(t("settings.rotateV2SuccessNotice"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("settings.rotateFailed"));
    } finally {
      zeroize(dataKey, authKey);
      if (newKeys) zeroize(newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
      if (newSalt) zeroize(newSalt);
      setBusy(false);
    }
  };

  /** The v1→v2 self-upgrade (2026-09-26): wrap the CURRENT data key (the
   *  one this vault already holds) under a KEK derived from the password
   *  the user just typed, and upload it with two proofs — the verifier
   *  derived from the SAME typed password (a mistyped password fails the
   *  verifier server-side BEFORE any envelope is stored; storing an
   *  envelope under the wrong password would brick every future unlock)
   *  and a processing session opened with the current data key (the
   *  possession proof; 403 envelope_key_mismatch means the session key
   *  did not authenticate stored ciphertext — sign in fresh and retry).
   *  Nothing the account can see changes: same key, same journal, same
   *  grants; only future password changes become O(1). */
  const upgradeKeyProtection = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    const username = sessionUsername();
    if (!owner || !username || !vault.isUnlocked() || !upgradePassword) {
      setError(t("common.sessionLocked"));
      return;
    }
    setBusy(true);
    setError("");
    setStatus(null);
    let typedKeys: PatientKeys | null = null;
    let saltBytes: Bytes | null = null;
    // 2026-09-28 audit (LOW, the moodLog/Entry M-3 idiom): snapshot the
    // data key BEFORE the awaits — vault.get()'s buffers are SHARED, and a
    // lock landing during the session open or the re-wrap zeroizes them,
    // so the wrap (and the upload) would otherwise run under all-zero
    // bytes. The copy dies in the finally.
    const dataKey = new Uint8Array(new ArrayBuffer(vault.get().dataKey.length));
    dataKey.set(vault.get().dataKey);
    try {
      const { salt } = await auth.saltFor(username);
      saltBytes = fromBase64(salt);
      // 2026-09-28 audit (LOW): derive and re-wrap under the account's
      // DECLARED params (the mount-time envelope read), not an implicit
      // 600k default — v1 accounts declare none, so the default holds
      // byte-for-byte there, but a params-bearing account must never have
      // its blob re-wrapped under params the stored AAD does not declare.
      const params = envelopeParams.current ?? KDF_PARAMS_DEFAULT;
      if (params.algorithm !== "pbkdf2-sha256") {
        // This build derives PBKDF2 only: refuse BEFORE any server step.
        setError(t("settings.kdfUnsupportedWeb"));
        return;
      }
      typedKeys = await derivePatientKeys(await deriveMasterKey(upgradePassword, saltBytes, params.iterations));
      const verifierB64 = toBase64(typedKeys.authKey);
      const session = await api.openProcessingSession(toBase64(dataKey));
      if (!vault.isUnlocked()) {
        // A lock during the session open: nothing has moved server-side —
        // abort honestly instead of uploading an envelope under a dead
        // session's authorization.
        setError(t("common.sessionLocked"));
        return;
      }
      const wrappedDataKeyB64 = await rewrapDataKey(dataKey, typedKeys.masterKey, saltBytes, username, params);
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
        return;
      }
      await api.upgradeKeyEnvelope(
        wrappedDataKeyB64,
        params as unknown as Record<string, unknown>,
        session.session_token,
        verifierB64,
      );
      setKeyScheme("v2");
      setStatus(t("settings.upgradeDoneNote"));
    } catch (err) {
      if (err instanceof ApiError && err.code === "envelope_key_mismatch") {
        setError(t("settings.upgradeKeyMismatchNote"));
      } else {
        setError(err instanceof Error ? err.message : t("settings.upgradeFailedNote"));
      }
    } finally {
      zeroize(dataKey);
      if (typedKeys) zeroize(typedKeys.masterKey, typedKeys.authKey, typedKeys.dataKey);
      if (saltBytes) zeroize(saltBytes);
      setUpgradePassword("");
      setBusy(false);
    }
  };

  const deleteAccount = async (): Promise<void> => {
    if (!vault.isUnlocked()) return;
    if (deleteText.trim().toUpperCase() !== "DELETE") {
      setError(t("settings.deleteTypeDelete"));
      return;
    }
    setBusy(true);
    setError("");
    const owner = vault.ownerUserId();
    try {
      await api.deleteAccount(toBase64(vault.get().authKey));
      if (owner) {
        // M-W3 (audit 2026-09-26): deletion leaves no per-account trace in
        // this browser's IndexedDB either — the offline queue (items,
        // rejected, quarantine), the entry-version high-water marks, the
        // analysis-generation mark, the encrypted mood log, the question
        // feedback queue, the encrypted pending-measure record, and the
        // encrypted pattern-mute set all go with the account.
        await Promise.allSettled([
          clearFeedback(owner),
          clearMoodLog(owner),
          clearQueue(owner),
          clearActiveDraft(owner),
          clearSafetyPlan(owner),
          clearMeasureCadence(owner),
          clearPendingMeasure(owner),
          forgetAllEntryVersions(owner),
          forgetAnalysisGeneration(owner),
          clearMutedPids(owner),
        ]);
      }
      // W-6 (audit 2026-09-25): account deletion leaves no per-account
      // trace in this browser either — the non-content mindpattern.* flags
      // (onboarding/mute/threshold stamps) go with the account.
      localStore.removePrefix("mindpattern.");
      props.onLockdown(t("settings.deleteDoneNotice"));
    } catch (err) {
      setError(err instanceof Error ? err.message : t("settings.deleteFailed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <ErrorBanner message={error} />
      {status && <PillNote role="status" tone="ok" icon="check">{status}</PillNote>}

      <Card title={t("settings.appearanceTitle")}>
        <Note tone="muted">{t("settings.themeNote")}</Note>
        <SegmentedControl
          options={[
            { id: "light", label: t("settings.themeLight") },
            { id: "dark", label: t("settings.themeDark") },
            { id: "auto", label: t("settings.themeSystem") },
          ]}
          activeId={themePref}
          onSelect={chooseTheme}
          a11yLabel={t("settings.appearanceTitle")}
        />
        <hr className="divider" />
        <Note tone="muted">{t("settings.languageNote")}</Note>
        <SegmentedControl
          options={[
            { id: "auto", label: t("settings.languageAuto") },
            { id: "en", label: t("settings.languageEn") },
            { id: "es", label: t("settings.languageEs") },
          ]}
          activeId={languagePref}
          onSelect={chooseLanguage}
          a11yLabel={t("settings.languageA11y")}
        />
      </Card>

      <Card title={t("settings.cadenceTitle")}>
        {cadence === null ? (
          <Note role="status">{t("common.loading")}</Note>
        ) : (
          <>
            <Toggle
              checked={cadence.enabled}
              onChange={(enabled) => chooseCadence({ ...cadence, enabled })}
              disabled={busy}
              label={t("settings.remindMeasures")}
            />
            {cadence.enabled && (
              <>
                <Note tone="muted">{t("settings.remindMeasuresNote")}</Note>
                <SegmentedControl
                  options={CADENCE_INTERVALS.map((weeks) => ({ id: String(weeks), label: t(`measures.cadence.${weeks}`) }))}
                  activeId={String(cadence.intervalWeeks)}
                  onSelect={(id) => chooseCadence({ ...cadence, intervalWeeks: Number(id) as MeasureCadencePref["intervalWeeks"] })}
                  a11yLabel={t("settings.cadenceIntervalA11y")}
                />
              </>
            )}
          </>
        )}
      </Card>

      {props.onOpenSafetyPlan && (
        <Card title={t("plan.title")}>
          <Note tone="muted">{t("settings.safetyPlanNote")}</Note>
          <Button label={t("settings.openSafetyPlan")} onPress={props.onOpenSafetyPlan} small variant="ghost" icon="heart" />
        </Card>
      )}

      <Card title={t("settings.privacyDataTitle")}>
        {llmLoad === "known" && llm && (
          llm.available ? (
            <Toggle
              checked={llm.enabled}
              onChange={(enabled) => void toggleLlm(enabled)}
              disabled={busy}
              label={llm.enabled ? t("settings.llmStatusEnabled") : t("settings.llmStatusOff")}
            />
          ) : (
            <Note tone="muted">{t("settings.llmNotOffered")}</Note>
          )
        )}
        {/* LOW b (audit 2026-09-26): a failed meta/consent read renders an
            explicit unknown state with a retry — the section must not
            silently disappear. */}
        {llmLoad === "unknown" && (
          <>
            <Note tone="warn">{t("settings.llmUnknown")}</Note>
            <Button label={t("settings.llmRetry")} onPress={() => void load()} small variant="ghost" disabled={busy} />
          </>
        )}
        {llmLoad === "loading" && <Note role="status">{t("common.loading")}</Note>}
        <hr className="divider" />
        <div className="row row--wrap">
          <Button label={t("settings.export")} onPress={() => void exportData()} small variant="ghost" disabled={busy} />
        </div>
        <Note tone="muted">{t("settings.exportNote")}</Note>
        {queued !== null && queued > 0 && <Note tone="warn">{t(queued === 1 ? "settings.queuedOne" : "settings.queuedMany", { count: queued })}</Note>}
        {rejected > 0 && (
          <>
            <Note tone="warn">{t(rejected === 1 ? "settings.rejectedOne" : "settings.rejectedMany", { count: rejected })}</Note>
            <Button label={t("settings.requeue")} onPress={() => void recoverQueue()} small variant="ghost" disabled={busy} />
          </>
        )}
      </Card>

      <Card title={t("settings.accessTitle")}>
        {accessRows === null && <Note role="status">{t("common.loading")}</Note>}
        {accessRows?.length === 0 && <Note>{t("settings.accessEmpty")}</Note>}
        {/* 2026-09-28 audit (INFO): a failed "Show more" keeps the rows
            already fetched and says so — never a silent wipe. */}
        {accessError && <Note tone="warn">{accessError}</Note>}
        {accessRows && accessRows.length > 0 && (
          <div className="timeline">
            {accessRows.map((row, index) => (
              <div key={index} className="timeline__row">
                <span className="mono" style={{ color: "var(--muted)", flex: "none" }}>{row.at.slice(0, 19).replace("T", " ")}</span>
                <span>{row.action}{row.actor && row.actor !== "self" ? ` (${row.actor})` : ""}</span>
              </div>
            ))}
          </div>
        )}
        {accessCursor && <Button label={t("settings.showMore")} onPress={() => void loadAccess(accessCursor)} small variant="ghost" />}
      </Card>

      {/* Password change, routed by the account's key scheme (2026-09-26):
          v2 accounts get the O(1) re-wrap (no re-encryption, honest copy);
          v1 accounts keep the full rekey flow below. An UNKNOWN scheme
          blocks the card — running the v1 flow against a v2 account would
          409 key_scheme_conflict at the very last step. */}
      <Card title={t("settings.rotateTitle")}>
        {keyScheme === null ? (
          <>
            <Note tone={schemeUnknown ? "warn" : "muted"}>{t("settings.schemeUnknownNote")}</Note>
            {schemeUnknown && (
              <Button label={t("settings.llmRetry")} onPress={() => void load()} small variant="ghost" disabled={busy} />
            )}
          </>
        ) : (
          <>
            <Note tone="muted">{t(keyScheme === "v2" ? "settings.rotateV2Note" : "settings.rotateNote")}</Note>
            <Field label={t("settings.newPasswordField")} value={newPassword} onChange={setNewPassword} type="password" autoComplete="new-password" />
            <Field label={t("settings.confirmPasswordField")} value={confirmPassword} onChange={setConfirmPassword} type="password" autoComplete="new-password" />
            <Button
              label={busy ? t("settings.working") : t("settings.changePasswordButton")}
              onPress={() => void (keyScheme === "v2" ? rotatePasswordV2() : rotatePassword())}
              disabled={busy}
            />
          </>
        )}
      </Card>

      {/* v1 accounts only (2026-09-26): the self-service upgrade to the v2
          key envelope. Collapsed to a single confirm-with-password action —
          nothing is derived, fetched, or sent until the user asks. */}
      {keyScheme === "v1" && (
        <Card title={t("settings.upgradeTitle")}>
          <Note tone="muted">{t("settings.upgradeNote")}</Note>
          <Field label={t("settings.upgradePasswordField")} value={upgradePassword} onChange={setUpgradePassword} type="password" autoComplete="current-password" />
          <Button label={busy ? t("settings.working") : t("settings.upgradeButton")} onPress={() => void upgradeKeyProtection()} disabled={busy || upgradePassword.length === 0} />
        </Card>
      )}

      <Card title={t("settings.deleteTitle")} tone="danger">
        <Note tone="danger">{t("settings.deleteNote")}</Note>
        <Field label={t("settings.deleteConfirmLabel")} value={deleteText} onChange={setDeleteText} autoComplete="off" />
        {/* Disabled until the confirmation text is exactly DELETE (E2E
            2026-09-26, finding F3) — the handler keeps its own guard so a
            synthetic click path still cannot delete unconfirmed. */}
        <Button
          label={t("settings.deleteButton")}
          onPress={() => void deleteAccount()}
          danger
          disabled={busy || deleteText.trim().toUpperCase() !== "DELETE"}
        />
      </Card>
    </>
  );
}
