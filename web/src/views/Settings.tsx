/**
 * Settings (WEB_PLAN P7.3–7.6): LLM consent (re-authenticated), the access
 * log ("who accessed my data"), the web-first ciphertext export download,
 * queue recovery, verifier-gated account deletion with the retention
 * honesty note, and the full password-rotation flow — rekey the corpus
 * (two single-use processing sessions), re-wrap every active therapist
 * grant, THEN rotate the credential (which kills every session everywhere).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type ListedConsent } from "../api/client";
import { deriveMasterKey, toBase64, zeroize, type Bytes } from "../crypto/core";
import { decryptEntry } from "../crypto/patient";
import { wrapDataKeyForTherapist } from "../crypto/sharing";
import { derivePatientKeys, type PatientKeys } from "../crypto/keys";
import { rebindEntryVersions, forgetAllEntryVersions } from "../entryVersions";
import { requeueRejected, rejectedEntries, queueLength, clearQueue } from "../offlineQueue";
import { downloadTextFile, localStore, randomBytes } from "../platform";
import { clearMoodLog } from "../moodLog";
import { clearFeedback } from "../questionFeedback";
import { clearMutedPids } from "../patternMutes";
import { forgetAnalysisGeneration } from "../stateSeqGuard";
import { t } from "../strings";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Field, Note } from "../ui";

/** Resume-ladder step (H-4/M-W2, audit 2026-09-26 — port of mobile
 *  rotation.ts newKeyReadsJournal): can the CANDIDATE new key decrypt at
 *  least one live entry? Proves a rekey_key_mismatch means "already
 *  rekeyed by an earlier attempt with THIS password" rather than "wrong
 *  key", so the flow may continue from the rewrap stage. An empty journal
 *  trivially verifies — there is nothing to mismatch. */
async function newKeyReadsJournal(userId: string, newDataKey: Bytes): Promise<boolean> {
  try {
    const page = await api.listEntriesPage({ limit: 1, offset: 0 });
    if (page.entries.length === 0) return true;
    const entry = page.entries[0]!;
    if (typeof entry.blob !== "string") return false;
    try {
      await decryptEntry(newDataKey, userId, entry.client_entry_id, entry.blob, entry.content_version ?? undefined);
      return true;
    } catch {
      return false;
    }
  } catch {
    // The probe itself failed (offline/5xx): unverifiable, so not "readable".
    return false;
  }
}

export function SettingsView(props: { onLockdown: (notice: string) => void }): React.JSX.Element {
  const [llm, setLlm] = useState<{ available: boolean; enabled: boolean } | null>(null);
  // 2026-09-26 audit LOW b: a FAILED meta/consent read is an explicit
  // unknown state with a retry — the LLM section used to vanish silently.
  const [llmLoad, setLlmLoad] = useState<"loading" | "known" | "unknown">("loading");
  const [accessRows, setAccessRows] = useState<{ at: string; action: string; actor: string }[] | null>(null);
  const [accessCursor, setAccessCursor] = useState<string | null>(null);
  const [queued, setQueued] = useState<number | null>(null);
  const [rejected, setRejected] = useState<number>(0);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [deleteText, setDeleteText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    if (!vault.isUnlocked()) return;
    setLlmLoad("loading");
    const [meta, consentState] = await Promise.all([
      api.meta().catch(() => null),
      api.getLlmConsent().catch(() => null),
    ]);
    if (generation.current !== run) return;
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
    }
    await loadAccess();
  }, []);

  const loadAccess = useCallback(async (cursor?: string): Promise<void> => {
    try {
      const page = await api.accessLogPage(cursor);
      setAccessRows((current) => (cursor && current ? [...current, ...page.rows] : page.rows));
      setAccessCursor(page.nextCursor);
    } catch {
      setAccessRows([]);
      setAccessCursor(null);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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
    if (newPassword.length < 12) {
      setError(t("settings.pwTooShort"));
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
      const newSalt = randomBytes(16);
      const newSaltB64 = toBase64(newSalt);
      newKeys = await derivePatientKeys(await deriveMasterKey(newPassword, newSalt));

      let oldB64 = "";
      for (const byte of old.dataKey) oldB64 += String.fromCharCode(byte);
      let newB64 = "";
      for (const byte of newKeys.dataKey) newB64 += String.fromCharCode(byte);
      const oldSession = await api.openProcessingSession(btoa(oldB64));
      const newSession = await api.openProcessingSession(btoa(newB64));
      try {
        await api.rekeyStoredData(oldSession.session_token, newSession.session_token, toBase64(old.authKey));
        serverMovedToNewKey = true;
      } catch (err) {
        if (err instanceof ApiError && err.code === "rekey_key_mismatch") {
          // Resume ladder (mobile rotation.ts:131-152): a previous attempt
          // already moved the blobs to a new key. Continue ONLY if the key
          // we are about to make current can actually read the journal;
          // otherwise the honest stop — never a false "NOTHING changed".
          if (!(await newKeyReadsJournal(owner, newKeys.dataKey))) {
            setError(t("settings.rotateAlreadyRotated"));
            return;
          }
          serverMovedToNewKey = true; // idempotent completion from rewrap on
        } else {
          throw err;
        }
      }

      // Re-wrap every active grant to the therapists' CURRENT public keys
      // (the old wraps open the old data key, which is now dead).
      const consents: ListedConsent[] = await api.listConsents();
      for (const consent of consents) {
        if (consent.status !== "active" || !consent.therapist_wrap_pub_key) continue;
        const wrap = await wrapDataKeyForTherapist(newKeys.dataKey, consent.therapist_wrap_pub_key, owner, consent.therapist_id);
        await api.rewrapConsent(consent.id, wrap.ephemeralPubB64, wrap.wrappedKeyB64, toBase64(old.authKey));
      }

      await api.rotateCredential(toBase64(old.authKey), newSaltB64, toBase64(newKeys.authKey));
      await rebindEntryVersions(owner, old.dataKey, newKeys.dataKey).catch(() => forgetAllEntryVersions(owner));
      // Mobile rotation parity: the mood log, question feedback, and
      // pattern mutes are sealed under the OLD data key — clear them (each
      // rebuilds on next use under the new key).
      await clearMoodLog(owner).catch(() => undefined);
      await clearFeedback(owner).catch(() => undefined);
      await clearMutedPids(owner).catch(() => undefined);
      props.onLockdown(t("settings.rotateSuccessNotice"));
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
        // feedback queue, and the encrypted pattern-mute set all go with
        // the account.
        await Promise.allSettled([
          clearFeedback(owner),
          clearMoodLog(owner),
          clearQueue(owner),
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
      <Card title={t("settings.title")}>
        {llmLoad === "known" && llm && (
          llm.available ? (
            <>
              <Note>{llm.enabled ? t("settings.llmStatusEnabled") : t("settings.llmStatusOff")}</Note>
              <Button label={llm.enabled ? t("settings.llmDisable") : t("settings.llmEnable")} onPress={() => void toggleLlm(!llm.enabled)} small danger={llm.enabled} disabled={busy} />
            </>
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
            <Button label={t("settings.llmRetry")} onPress={() => void load()} small disabled={busy} />
          </>
        )}
        {llmLoad === "loading" && <Note role="status">{t("common.loading")}</Note>}
        <ErrorBanner message={error} />
        {status && <Note role="status" tone="ok">{status}</Note>}
      </Card>

      <Card title={t("settings.dataTitle")}>
        <Button label={t("settings.export")} onPress={() => void exportData()} small disabled={busy} />
        <Note tone="muted">{t("settings.exportNote")}</Note>
        {queued !== null && queued > 0 && <Note tone="warn">{t(queued === 1 ? "settings.queuedOne" : "settings.queuedMany", { count: queued })}</Note>}
        {rejected > 0 && (
          <>
            <Note tone="warn">{t(rejected === 1 ? "settings.rejectedOne" : "settings.rejectedMany", { count: rejected })}</Note>
            <Button label={t("settings.requeue")} onPress={() => void recoverQueue()} small disabled={busy} />
          </>
        )}
      </Card>

      <Card title={t("settings.accessTitle")}>
        {accessRows === null && <Note role="status">{t("common.loading")}</Note>}
        {accessRows?.length === 0 && <Note>{t("settings.accessEmpty")}</Note>}
        {accessRows?.map((row, index) => (
          <Note key={index} tone="muted">{`${row.at.slice(0, 19).replace("T", " ")} — ${row.action}${row.actor && row.actor !== "self" ? ` (${row.actor})` : ""}`}</Note>
        ))}
        {accessCursor && <Button label={t("settings.showMore")} onPress={() => void loadAccess(accessCursor)} small />}
      </Card>

      <Card title={t("settings.rotateTitle")}>
        <Note tone="muted">{t("settings.rotateNote")}</Note>
        <Field label={t("settings.newPasswordField")} value={newPassword} onChange={setNewPassword} type="password" autoComplete="new-password" />
        <Field label={t("settings.confirmPasswordField")} value={confirmPassword} onChange={setConfirmPassword} type="password" autoComplete="new-password" />
        <Button label={busy ? t("settings.working") : t("settings.changePasswordButton")} onPress={() => void rotatePassword()} disabled={busy} />
      </Card>

      <Card title={t("settings.deleteTitle")}>
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
