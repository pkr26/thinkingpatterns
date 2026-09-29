/**
 * Therapist sharing (WEB_PLAN P7.2): the patient side of the zero-knowledge
 * consent. Pairing shows the therapist's NAME, their key FINGERPRINT, and
 * — since the 2026-09-26 wave — the pairing session's SAS ("123 456") plus
 * the server's wrap-key fingerprint: the out-of-band checks the two humans
 * read to each other (a matching SAS is the human proof the key was not
 * substituted; the therapist's portal derives the identical string for the
 * same live pairing session). Granting requires BOTH attestations — an
 * explicit "fingerprints matched" confirmation (mobile C-7 parity, fix
 * W-4, audit 2026-09-25) and the disclosure terms — then wraps the data
 * key to the therapist's public key (ECDH→HKDF→AES-GCM) with the
 * password-derived verifier: a stolen token cannot share. Revoke is
 * verifier-gated too and says plainly what revocation can and cannot do.
 *
 * Redesign 2026-09-26: styled checkboxes, the fingerprint in a mono block
 * with a copy affordance, grants as cards with initials avatars, and a
 * two-step revoke confirm.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type ListedConsent } from "../api/client";
import { toBase64, zeroize } from "../crypto/core";
import { keyFingerprint, wrapDataKeyForTherapist } from "../crypto/sharing";
import { t } from "../strings";
import { vault } from "../vault";
import { Avatar, Button, Card, Checkbox, ErrorBanner, Field, Icon, Note, PillNote, Toggle } from "../ui";

export function ShareView(): React.JSX.Element {
  const [consents, setConsents] = useState<ListedConsent[] | null>(null);
  const [code, setCode] = useState("");
  const [lookup, setLookup] = useState<{
    name: string;
    fingerprint: string;
    therapistId: string;
    wrapPubKey: string;
    /** SAS verification (2026-09-26): both null on a backend predating
     *  the wave — the block simply hides (the local fingerprint check,
     *  computed below, stays either way). */
    sas: string | null;
    serverFingerprint: string | null;
  } | null>(null);
  const [disclosureAccepted, setDisclosureAccepted] = useState(false);
  const [fingerprintVerified, setFingerprintVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [armedRevoke, setArmedRevoke] = useState<string | null>(null);
  const generation = useRef(0);

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
      setError(err instanceof Error ? err.message : t("share.webLoadFailed"));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const doLookup = async (): Promise<void> => {
    setError("");
    setStatus(null);
    setLookup(null);
    setCopied(false);
    setDisclosureAccepted(false);
    setFingerprintVerified(false);
    if (!code.trim()) {
      setError(t("share.webCodeRule"));
      return;
    }
    setBusy(true);
    try {
      const found = await api.pairingLookup(code.trim());
      setLookup({
        name: found.display_name,
        therapistId: found.therapist_id,
        wrapPubKey: found.wrap_pub_key,
        fingerprint: await keyFingerprint(found.wrap_pub_key),
        // Server-provided comparison strings (optional fields): strings or
        // nothing — anything else degrades to hidden, never a broken render.
        sas: typeof found.sas === "string" ? found.sas : null,
        serverFingerprint: typeof found.wrap_key_fingerprint === "string" ? found.wrap_key_fingerprint : null,
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setError(t("share.webCodeExpired"));
      else setError(err instanceof Error ? err.message : t("share.webLookupFailed"));
    } finally {
      setBusy(false);
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

  const grant = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked() || !lookup) return;
    setBusy(true);
    setError("");
    // 2026-09-28 audit (LOW, the moodLog/Entry M-3 idiom): snapshot BOTH
    // vault buffers BEFORE the awaits — vault.get()'s buffers are SHARED,
    // and a lock landing during the wrap await zeroizes them, so the grant
    // would otherwise upload a wrap of the data key under all-zero bytes
    // (and a zero verifier). The copies die in the finally; a lock at any
    // re-check aborts with the honest locked message instead.
    const keys = vault.get();
    const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
    dataKey.set(keys.dataKey);
    const authKey = new Uint8Array(new ArrayBuffer(keys.authKey.length));
    authKey.set(keys.authKey);
    try {
      const wrap = await wrapDataKeyForTherapist(dataKey, lookup.wrapPubKey, owner, lookup.therapistId);
      if (!vault.isUnlocked()) {
        setError(t("common.sessionLocked"));
        return;
      }
      await api.grantConsent(code.trim(), wrap.ephemeralPubB64, wrap.wrappedKeyB64, toBase64(authKey));
      setStatus(t("share.webGrantedStatus", { name: lookup.name }));
      setCode("");
      setLookup(null);
      setCopied(false);
      setDisclosureAccepted(false);
      setFingerprintVerified(false);
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === "disclosure_outdated") {
        setError(t("share.webTermsChanged"));
      } else {
        setError(err instanceof Error ? err.message : t("share.webGrantFailed"));
      }
    } finally {
      zeroize(dataKey, authKey);
      setBusy(false);
    }
  };

  const revoke = async (consent: ListedConsent): Promise<void> => {
    if (!vault.isUnlocked()) return;
    setBusy(true);
    setError("");
    try {
      await api.revokeConsent(consent.id, toBase64(vault.get().authKey));
      setStatus(t("share.webRevokedStatus", { name: consent.display_name }));
      setArmedRevoke(null);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("share.webRevokeFailed"));
    } finally {
      setBusy(false);
    }
  };

  /** Share-voice toggle (VOICE_PLAN 2026-09-29): verifier-gated like every
   *  scope change on a live grant; optimistic-failure honest (reload on
   *  error). */
  const toggleShareVoice = async (consent: ListedConsent, enabled: boolean): Promise<void> => {
    setBusy(true);
    setError("");
    try {
      await api.setShareVoice(consent.id, enabled, toBase64(vault.get().authKey));
      setConsents((current) =>
        (current ?? []).map((row) => (row.id === consent.id ? { ...row, share_voice: enabled } : row)),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : t("share.webRevokeFailed"));
      const rows = await api.listConsents().catch(() => null);
      if (rows) setConsents(rows);
    } finally {
      setBusy(false);
    }
  };

  const active = consents?.filter((consent) => consent.status === "active") ?? [];
  const past = consents?.filter((consent) => consent.status !== "active") ?? [];

  return (
    <>
      <Card title={t("share.webTitle")}>
        <Note tone="muted">{t("share.webZeroKnowledge")}</Note>
        <Field label={t("share.webPairingCode")} value={code} onChange={setCode} placeholder={t("share.webPairingPlaceholder")} />
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
            <Button label={t("share.webConfirmShare")} onPress={() => void grant()} disabled={busy || !disclosureAccepted || !fingerprintVerified} icon="share" />
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
              onChange={(enabled) => void toggleShareVoice(consent, enabled)}
              disabled={busy}
              label={consent.share_voice === true ? t("share.voiceOn") : t("share.voiceOff")}
            />
            {consent.share_voice === true && <Note tone="muted">{t("share.voiceNote")}</Note>}
            {armedRevoke === consent.id ? (
              <div className="row row--wrap">
                <Button label={t("share.webRevoke")} onPress={() => void revoke(consent)} small danger disabled={busy} />
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
