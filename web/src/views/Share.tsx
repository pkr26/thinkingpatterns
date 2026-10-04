/**
 * Patient consent and key wrapping for therapist access.
 *
 * Pairing displays the therapist identity, key fingerprint, and short
 * authentication string for out-of-band verification. Granting requires
 * fingerprint and disclosure attestations plus a fresh, action-bound proof.
 * Revocation uses its own proof and explains the limits of withdrawing access.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, sessionAbortSignal, type ListedConsent } from "../api/client";
import { zeroize } from "../crypto/core";
import { keyFingerprint, wrapDataKeyForTherapist } from "../crypto/sharing";
import { freshStepUp } from "../reauth";
import { t } from "../strings";
import { displayError } from "../errors";
import { vault } from "../vault";
import { Avatar, Button, Card, Checkbox, ErrorBanner, Field, Note, PillNote, Toggle } from "../ui";

interface LookupState {
  code: string;
  name: string;
  fingerprint: string;
  therapistId: string;
  wrapPubKey: string;
  sas: string | null;
  serverFingerprint: string | null;
}

type PendingSensitiveAction =
  | { kind: "grant"; lookup: LookupState }
  | { kind: "revoke"; consent: ListedConsent }
  | { kind: "voice"; consent: ListedConsent; enabled: boolean };

export function ShareView(): React.JSX.Element {
  const [consents, setConsents] = useState<ListedConsent[] | null>(null);
  const [code, setCode] = useState("");
  const [lookup, setLookup] = useState<LookupState | null>(null);
  const [disclosureAccepted, setDisclosureAccepted] = useState(false);
  const [fingerprintVerified, setFingerprintVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [armedRevoke, setArmedRevoke] = useState<string | null>(null);
  const [pendingSensitive, setPendingSensitive] = useState<PendingSensitiveAction | null>(null);
  const [reauthPassword, setReauthPassword] = useState("");
  const generation = useRef(0);
  const pairingGeneration = useRef(0);
  const mounted = useRef(true);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    if (!vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    try {
      const rows = await api.listConsents();
      if (generation.current !== run) return;
      setConsents(rows);
    } catch (err) {
      if (generation.current !== run) return;
      setError(displayError(err, t("share.webLoadFailed")));
    }
  }, []);

  useEffect(() => {
    mounted.current = true;
    void load();
    return () => { mounted.current = false; generation.current += 1; pairingGeneration.current += 1; };
  }, [load]);

  const doLookup = async (): Promise<void> => {
    const operation = ++pairingGeneration.current;
    const pairingCode = code.trim();
    const signal = sessionAbortSignal();
    const current = (): boolean => mounted.current && operation === pairingGeneration.current && !!signal && !signal.aborted;
    setError("");
    setStatus(null);
    setLookup(null);
    setCopied(false);
    setDisclosureAccepted(false);
    setFingerprintVerified(false);
    if (!pairingCode) {
      setError(t("share.webCodeRule"));
      return;
    }
    setBusy(true);
    try {
      const found = await api.pairingLookup(pairingCode);
      if (!current()) return;
      const fingerprint = await keyFingerprint(found.wrap_pub_key);
      if (!current()) return;
      setLookup({
        code: pairingCode,
        name: found.display_name,
        therapistId: found.therapist_id,
        wrapPubKey: found.wrap_pub_key,
        fingerprint,
        // Server-provided comparison strings (optional fields): strings or
        // nothing — anything else degrades to hidden, never a broken render.
        sas: typeof found.sas === "string" ? found.sas : null,
        serverFingerprint: typeof found.wrap_key_fingerprint === "string" ? found.wrap_key_fingerprint : null,
      });
    } catch (err) {
      if (!current()) return;
      if (err instanceof ApiError && err.status === 404) setError(t("share.webCodeExpired"));
      else setError(displayError(err, t("share.webLookupFailed")));
    } finally {
      if (current()) setBusy(false);
    }
  };

  const copyFingerprint = async (): Promise<void> => {
    if (!lookup) return;
    try {
      await navigator.clipboard?.writeText(lookup.fingerprint);
      setCopied(true);
    } catch {
      // Clipboard unavailable (permissions, non-secure context): the
      // fingerprint stays selectable on screen either way.
    }
  };

  const requestGrant = (): void => {
    if (!vault.isUnlocked() || !lookup || lookup.code !== code.trim() || !disclosureAccepted || !fingerprintVerified) return;
    setError("");
    setReauthPassword("");
    setPendingSensitive({ kind: "grant", lookup: { ...lookup } });
  };

  const confirmSensitiveAction = async (): Promise<void> => {
    const pending = pendingSensitive;
    const owner = vault.ownerUserId();
    if (!pending || busy || !owner || !vault.isUnlocked()) return;
    const operation = pairingGeneration.current;
    const signal = sessionAbortSignal();
    const keys = vault.get();
    const current = (): boolean => mounted.current && operation === pairingGeneration.current && !!signal && !signal.aborted && vault.isUnlocked() && vault.ownerUserId() === owner && vault.get().dataKey === keys.dataKey;
    const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
    dataKey.set(keys.dataKey);
    setBusy(true);
    setError("");
    try {
      const action = pending.kind === "grant"
        ? "sharing_grant"
        : pending.kind === "revoke"
          ? "sharing_revoke"
          : "sharing_voice";
      const wrap = pending.kind === "grant"
        ? await wrapDataKeyForTherapist(dataKey, pending.lookup.wrapPubKey, owner, pending.lookup.therapistId)
        : null;
      if (!current()) return;
      const stepped = await freshStepUp(reauthPassword, action);
      if (!current()) return;
      if (!stepped.ok) {
        const messages = {
          locked: t("common.reauthLocked"),
          "no-account": t("common.reauthNoAccount"),
          "wrong-password": t("common.wrongPassword"),
          offline: t("common.reauthOffline"),
        } as const;
        setError(messages[stepped.reason]);
        return;
      }
      if (pending.kind === "grant" && wrap) {
        await api.grantConsent(pending.lookup.code, wrap.ephemeralPubB64, wrap.wrappedKeyB64, stepped.proof);
      } else if (pending.kind === "revoke") {
        await api.revokeConsent(pending.consent.id, stepped.proof);
      } else if (pending.kind === "voice") {
        await api.setShareVoice(pending.consent.id, pending.enabled, stepped.proof);
      }
      if (!current()) return;
      if (pending.kind === "grant") {
        setStatus(t("share.webGrantedStatus", { name: pending.lookup.name }));
        setCode("");
        setLookup(null);
        setCopied(false);
        setDisclosureAccepted(false);
        setFingerprintVerified(false);
      } else if (pending.kind === "revoke") {
        setStatus(t("share.webRevokedStatus", { name: pending.consent.display_name }));
        setArmedRevoke(null);
      }
      setPendingSensitive(null);
      await load();
    } catch (err) {
      if (!current()) return;
      if (err instanceof ApiError && err.code === "disclosure_outdated") {
        setError(t("share.webTermsChanged"));
      } else if (pending.kind === "grant") {
        setError(t("share.webGrantFailed"));
      } else if (pending.kind === "revoke") {
        setError(t("share.webRevokeFailed"));
      } else {
        setError(t("share.voiceToggleFailed"));
        const rows = await api.listConsents().catch(() => null);
        if (rows) setConsents(rows);
      }
    } finally {
      zeroize(dataKey);
      setReauthPassword("");
      if (current()) setBusy(false);
    }
  };

  const requestRevoke = (consent: ListedConsent): void => {
    if (!vault.isUnlocked()) return;
    setError("");
    setReauthPassword("");
    setPendingSensitive({ kind: "revoke", consent });
  };

  /** Share-voice toggle (VOICE_PLAN 2026-09-29): fresh-step-up-gated like
   *  every scope change on a live grant; optimistic-failure honest (reload
   *  on error). */
  const toggleShareVoice = (consent: ListedConsent, enabled: boolean): void => {
    if (!vault.isUnlocked()) return;
    setError("");
    setReauthPassword("");
    setPendingSensitive({ kind: "voice", consent, enabled });
  };

  const active = consents?.filter((consent) => consent.status === "active") ?? [];
  const past = consents?.filter((consent) => consent.status !== "active") ?? [];

  return (
    <>
      {pendingSensitive && (
        <Card
          title={pendingSensitive.kind === "grant"
            ? t("share.reauthGrantTitle", { name: pendingSensitive.lookup.name })
            : pendingSensitive.kind === "voice"
              ? t("share.reauthShareVoiceTitle", { name: pendingSensitive.consent.display_name })
              : t("share.reauthRevokeTitle")}
          tone={pendingSensitive.kind === "revoke" ? "danger" : undefined}
        >
          <Note tone="muted">{t("settings.reauthFreshNote")}</Note>
          <Field
            label={t("settings.reauthPasswordField")}
            value={reauthPassword}
            onChange={setReauthPassword}
            type="password"
            autoComplete="current-password"
          />
          <div className="row row--wrap">
            <Button
              label={busy ? t("settings.working") : t("settings.reauthConfirm")}
              onPress={() => void confirmSensitiveAction()}
              disabled={busy || reauthPassword.length === 0}
              danger={pendingSensitive.kind === "revoke"}
            />
            <Button
              label={t("common.cancel")}
              onPress={() => { setPendingSensitive(null); setReauthPassword(""); }}
              disabled={busy}
              variant="ghost"
            />
          </div>
        </Card>
      )}
      <Card title={t("share.webTitle")}>
        <Note tone="muted">{t("share.webZeroKnowledge")}</Note>
        <Field label={t("share.webPairingCode")} value={code} onChange={(value) => { pairingGeneration.current += 1; setBusy(false); setCode(value); setLookup(null); setCopied(false); setFingerprintVerified(false); setDisclosureAccepted(false); }} placeholder={t("share.webPairingPlaceholder")} />
        <Button label={busy ? t("settings.working") : t("share.webLookUp")} onPress={() => void doLookup()} disabled={busy} small variant="ghost" />
        {lookup && (
          <>
            <Note role="status">{t("share.webTherapist", { name: lookup.name })}</Note>
            {/* SAS out-of-band verification (2026-09-26): the therapist's
                portal derives the SAME "123 456" for this live pairing
                session and shows it beside their own code entry. The two
                humans compare by voice; a mismatch means the key was
                substituted — do not continue. The patient's own account id
                rides along: it is the input the therapist's portal needs to
                pull up the same SAS (an opaque random id, safe to read
                aloud). */}
            {lookup.sas && (
              <div className="stack" style={{ gap: "var(--space-1)" }}>
                <span className="fingerprint">{lookup.sas}</span>
                {lookup.serverFingerprint && (
                  <Note tone="muted">{t("share.webSasKeyLabel", { fingerprint: lookup.serverFingerprint })}</Note>
                )}
                {vault.ownerUserId() && (
                  <Note tone="muted">{t("share.webSasOwnId", { id: vault.ownerUserId()! })}</Note>
                )}
                <Note tone="warn">{t("share.webSasCompareNote")}</Note>
              </div>
            )}
            <div className="stack" style={{ gap: "var(--space-1)" }}>
              <span className="fingerprint">{lookup.fingerprint}</span>
              <span className="row" style={{ gap: 8 }}>
                <Button label={copied ? t("share.copiedFingerprint") : t("share.copyFingerprint")} onPress={() => void copyFingerprint()} small variant="ghost" icon="copy" />
              </span>
            </div>
            <Note tone="warn">{t("share.webFingerprintWarn")}</Note>
            <Checkbox checked={fingerprintVerified} onChange={setFingerprintVerified}>
              {t("share.webFingerprintConfirm")}
            </Checkbox>
            <Checkbox checked={disclosureAccepted} onChange={setDisclosureAccepted}>
              {t("share.webDisclosureConfirm")}
            </Checkbox>
            <Button label={t("share.webConfirmShare")} onPress={requestGrant} disabled={busy || !disclosureAccepted || !fingerprintVerified} icon="share" />
          </>
        )}
        <ErrorBanner message={error} />
        {status && <PillNote role="status" tone="ok" icon="check">{status}</PillNote>}
      </Card>

      <Card title={t("share.webGrantsTitle")}>
        {consents === null && <Note role="status">{t("common.loading")}</Note>}
        {consents !== null && active.length === 0 && <Note>{t("share.webNoGrants")}</Note>}
        {active.map((consent) => (
          <div key={consent.id} className="entry-card">
            <div className="row" style={{ gap: 12, alignItems: "center" }}>
              <Avatar name={consent.display_name || consent.username} />
              <div className="stack" style={{ gap: 2, flex: 1 }}>
                <strong style={{ fontSize: "var(--text-md)", color: "var(--text)" }}>{consent.display_name || consent.username}</strong>
                <Note tone="muted">{t("share.webSinceDate", { date: consent.granted_at.slice(0, 10) })}</Note>
              </div>
            </div>
            <Toggle
              checked={consent.share_voice === true}
              onChange={(enabled) => toggleShareVoice(consent, enabled)}
              disabled={busy}
              label={consent.share_voice === true ? t("share.voiceOn") : t("share.voiceOff")}
            />
            {consent.share_voice === true && <Note tone="muted">{t("share.voiceNote")}</Note>}
            {armedRevoke === consent.id ? (
              <div className="row row--wrap">
                <Button label={t("share.webRevoke")} onPress={() => requestRevoke(consent)} small danger disabled={busy} />
                <Button label={t("common.cancel")} onPress={() => setArmedRevoke(null)} small variant="ghost" />
              </div>
            ) : (
              <div className="row row--end">
                <Button label={t("share.webRevoke")} onPress={() => setArmedRevoke(consent.id)} small danger disabled={busy} />
              </div>
            )}
          </div>
        ))}
        {past.length > 0 && (
          <Note tone="muted">{t("share.webRevokedList", { names: past.map((consent) => consent.display_name).join(", ") })}</Note>
        )}
      </Card>
    </>
  );
}
