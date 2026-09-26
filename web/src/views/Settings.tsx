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
import { auth } from "../api/client";
import { deriveMasterKey, toBase64 } from "../crypto/core";
import { wrapDataKeyForTherapist } from "../crypto/sharing";
import { rebindEntryVersions } from "../entryVersions";
import { requeueRejected, rejectedEntries, queueLength } from "../offlineQueue";
import { downloadTextFile, localStore, randomBytes } from "../platform";
import { clearMoodLog } from "../moodLog";
import { clearFeedback } from "../questionFeedback";
import { derivePatientKeys } from "../crypto/keys";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Field, Note } from "../ui";

export function SettingsView(props: { onLockdown: (notice: string) => void }): React.JSX.Element {
  const [llm, setLlm] = useState<{ available: boolean; enabled: boolean } | null>(null);
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
    const [meta, consentState] = await Promise.all([
      api.meta().catch(() => null),
      api.getLlmConsent().catch(() => null),
    ]);
    if (generation.current !== run) return;
    setLlm(meta && consentState ? { available: meta.llm_available, enabled: consentState.enabled } : null);
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
      setStatus(enabled ? "Optional LLM analysis enabled for your account only." : "Optional LLM analysis disabled.");
    } catch (err) {
      if (err instanceof ApiError && err.code === "llm_unavailable") setError("This server does not offer LLM analysis.");
      else setError(err instanceof Error ? err.message : "Could not change the setting.");
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
      setStatus(ok
        ? "Export downloaded — an encrypted bundle. It stays unreadable without your password (decrypt it offline with the repo's decrypt_export tool)."
        : "Your browser blocked the download — copy the bundle manually when the dialog opens.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Export failed.");
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
      setStatus(moved > 0 ? `${moved} recovered entr${moved === 1 ? "y" : "ies"} re-queued.` : "Nothing to recover.");
    } finally {
      setBusy(false);
    }
  };

  /** The full rotation (P7.4): rekey corpus → re-wrap grants → rotate the
   *  credential (epoch death everywhere, disclosed). Ordering is the
   *  mobile rotation.ts contract: the rekey MUST land while both keys are
   *  derivable; the credential rotation MUST be last (it kills the token). */
  const rotatePassword = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError("Your session locked — sign in again.");
      return;
    }
    if (newPassword.length < 12) {
      setError("New password: at least 12 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("The two new passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    const old = vault.get();
    try {
      const newSalt = randomBytes(16);
      const newSaltB64 = toBase64(newSalt);
      const newKeys = await derivePatientKeys(await deriveMasterKey(newPassword, newSalt));

      let oldB64 = "";
      for (const byte of old.dataKey) oldB64 += String.fromCharCode(byte);
      let newB64 = "";
      for (const byte of newKeys.dataKey) newB64 += String.fromCharCode(byte);
      const oldSession = await api.openProcessingSession(btoa(oldB64));
      const newSession = await api.openProcessingSession(btoa(newB64));
      await api.rekeyStoredData(oldSession.session_token, newSession.session_token, toBase64(old.authKey));

      // Re-wrap every active grant to the therapists' CURRENT public keys
      // (the old wraps open the old data key, which is now dead).
      const consents: ListedConsent[] = await api.listConsents();
      for (const consent of consents) {
        if (consent.status !== "active" || !consent.therapist_wrap_pub_key) continue;
        const wrap = await wrapDataKeyForTherapist(newKeys.dataKey, consent.therapist_wrap_pub_key, owner, consent.therapist_id);
        await api.rewrapConsent(consent.id, wrap.ephemeralPubB64, wrap.wrappedKeyB64, toBase64(old.authKey));
      }

      await api.rotateCredential(toBase64(old.authKey), newSaltB64, toBase64(newKeys.authKey));
      await rebindEntryVersions(owner, old.dataKey, newKeys.dataKey).catch(() => forgetAll(owner));
      props.onLockdown("Password changed. Every session — including the mobile app — was signed out. Sign in again with your new password.");
    } catch (err) {
      if (err instanceof ApiError && err.code === "rekey_key_mismatch") {
        setError("The re-encryption found data the old key could not open — NOTHING was changed. Refresh and try again.");
      } else {
        setError(err instanceof Error ? err.message : "Could not change the password.");
      }
    } finally {
      setBusy(false);
    }
  };

  const deleteAccount = async (): Promise<void> => {
    if (!vault.isUnlocked()) return;
    if (deleteText.trim().toUpperCase() !== "DELETE") {
      setError('Type DELETE to confirm — this cannot be undone.');
      return;
    }
    setBusy(true);
    setError("");
    const owner = vault.ownerUserId();
    try {
      await api.deleteAccount(toBase64(vault.get().authKey));
      if (owner) {
        await Promise.allSettled([clearFeedback(owner), clearMoodLog(owner)]);
      }
      // W-6 (audit 2026-09-25): account deletion leaves no per-account
      // trace in this browser either — the non-content mindpattern.* flags
      // (onboarding/mute/threshold stamps) go with the account.
      localStore.removePrefix("mindpattern.");
      props.onLockdown("Your account and everything in it were deleted. Only the access audit log (who read what, when — no content) survives, for accountability.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the account.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Card title="Settings">
        {llm && (
          llm.available ? (
            <>
              <Note>{`Optional LLM analysis: ${llm.enabled ? "ENABLED for your account" : "off"}. Enabling sends your journal text to a third-party provider (only after your 30-day threshold, only for you, only while enabled).`}</Note>
              <Button label={llm.enabled ? "Disable LLM analysis" : "Enable LLM analysis"} onPress={() => void toggleLlm(!llm.enabled)} small danger={llm.enabled} disabled={busy} />
            </>
          ) : (
            <Note tone="muted">Optional LLM analysis is not offered by this server.</Note>
          )
        )}
        <ErrorBanner message={error} />
        {status && <Note role="status" tone="ok">{status}</Note>}
      </Card>

      <Card title="Your data">
        <Button label="Download export (encrypted)" onPress={() => void exportData()} small disabled={busy} />
        <Note tone="muted">{"The bundle is ciphertext — safe to store anywhere, unreadable without your password."}</Note>
        {queued !== null && queued > 0 && <Note tone="warn">{`${queued} entr${queued === 1 ? "y" : "ies"} still queued offline.`}</Note>}
        {rejected > 0 && (
          <>
            <Note tone="warn">{`${rejected} recovered entr${rejected === 1 ? "y" : "ies"} held back after server refusals.`}</Note>
            <Button label="Re-queue recovered entries" onPress={() => void recoverQueue()} small disabled={busy} />
          </>
        )}
      </Card>

      <Card title="Who accessed your data">
        {accessRows === null && <Note role="status">Loading…</Note>}
        {accessRows?.length === 0 && <Note>No recorded access beyond your own yet.</Note>}
        {accessRows?.map((row, index) => (
          <Note key={index} tone="muted">{`${row.at.slice(0, 19).replace("T", " ")} — ${row.action}${row.actor && row.actor !== "self" ? ` (${row.actor})` : ""}`}</Note>
        ))}
        {accessCursor && <Button label="Show more" onPress={() => void loadAccess(accessCursor)} small />}
      </Card>

      <Card title="Change password">
        <Note tone="muted">{"Re-encrypts your entire journal under the new password, re-wraps every therapist grant, and signs out every device — including the mobile app."}</Note>
        <Field label="New password" value={newPassword} onChange={setNewPassword} type="password" autoComplete="new-password" />
        <Field label="Confirm new password" value={confirmPassword} onChange={setConfirmPassword} type="password" autoComplete="new-password" />
        <Button label={busy ? "Working…" : "Change password"} onPress={() => void rotatePassword()} disabled={busy} />
      </Card>

      <Card title="Delete account">
        <Note tone="danger">{"Removes you and the full cascade: entries, patterns, questions, measures, sharing grants. Only the access audit log survives (metadata, no content). This cannot be undone."}</Note>
        <Field label='Type DELETE to confirm' value={deleteText} onChange={setDeleteText} autoComplete="off" />
        <Button label="Delete my account" onPress={() => void deleteAccount()} danger disabled={busy} />
      </Card>
    </>
  );
}

async function forgetAll(userId: string): Promise<void> {
  const { forgetAllEntryVersions } = await import("../entryVersions");
  await forgetAllEntryVersions(userId).catch(() => undefined);
}
