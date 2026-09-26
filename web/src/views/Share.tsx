/**
 * Therapist sharing (WEB_PLAN P7.2): the patient side of the zero-knowledge
 * consent. Pairing shows the therapist's NAME and their key FINGERPRINT —
 * the out-of-band check (read it back to each other; a matching fingerprint
 * is the human proof the key was not substituted). Granting requires BOTH
 * attestations — an explicit "fingerprints matched" confirmation (mobile
 * C-7 parity, fix W-4, audit 2026-09-25) and the disclosure terms — then
 * wraps the data key to the therapist's public key (ECDH→HKDF→AES-GCM)
 * with the password-derived verifier: a stolen token cannot share. Revoke
 * is verifier-gated too and says plainly what revocation can and cannot do.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type ListedConsent } from "../api/client";
import { toBase64 } from "../crypto/core";
import { keyFingerprint, wrapDataKeyForTherapist } from "../crypto/sharing";
import { t } from "../strings";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Field, Note } from "../ui";

export function ShareView(): React.JSX.Element {
  const [consents, setConsents] = useState<ListedConsent[] | null>(null);
  const [code, setCode] = useState("");
  const [lookup, setLookup] = useState<{ name: string; fingerprint: string; therapistId: string; wrapPubKey: string } | null>(null);
  const [disclosureAccepted, setDisclosureAccepted] = useState(false);
  const [fingerprintVerified, setFingerprintVerified] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState<string | null>(null);
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
      });
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) setError(t("share.webCodeExpired"));
      else setError(err instanceof Error ? err.message : t("share.webLookupFailed"));
    } finally {
      setBusy(false);
    }
  };

  const grant = async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked() || !lookup) return;
    setBusy(true);
    setError("");
    try {
      const keys = vault.get();
      const wrap = await wrapDataKeyForTherapist(keys.dataKey, lookup.wrapPubKey, owner, lookup.therapistId);
      await api.grantConsent(code.trim(), wrap.ephemeralPubB64, wrap.wrappedKeyB64, toBase64(keys.authKey));
      setStatus(t("share.webGrantedStatus", { name: lookup.name }));
      setCode("");
      setLookup(null);
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
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("share.webRevokeFailed"));
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
        <Button label={busy ? t("settings.working") : t("share.webLookUp")} onPress={() => void doLookup()} disabled={busy} small />
        {lookup && (
          <>
            <Note role="status">{t("share.webTherapist", { name: lookup.name })}</Note>
            <Note>{t("share.webFingerprint", { fingerprint: lookup.fingerprint })}</Note>
            <Note tone="warn">{t("share.webFingerprintWarn")}</Note>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 13, color: themeBody }}>
              <input type="checkbox" checked={fingerprintVerified} onChange={(e) => setFingerprintVerified(e.target.checked)} />
              <span>
                {t("share.webFingerprintConfirm")}
              </span>
            </label>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 13, color: themeBody }}>
              <input type="checkbox" checked={disclosureAccepted} onChange={(e) => setDisclosureAccepted(e.target.checked)} />
              <span>
                {t("share.webDisclosureConfirm")}
              </span>
            </label>
            <Button label={t("share.webConfirmShare")} onPress={() => void grant()} disabled={busy || !disclosureAccepted || !fingerprintVerified} />
          </>
        )}
        <ErrorBanner message={error} />
        {status && <Note role="status" tone="ok">{status}</Note>}
      </Card>

      <Card title={t("share.webGrantsTitle")}>
        {consents === null && <Note role="status">{t("common.loading")}</Note>}
        {consents !== null && active.length === 0 && <Note>{t("share.webNoGrants")}</Note>}
        {active.map((consent) => (
          <div key={consent.id} style={{ display: "flex", flexDirection: "column", gap: 6, borderTop: "1px solid #dfe5ec", paddingTop: 10 }}>
            <Note>{t("share.webSince", { name: consent.display_name, username: consent.username, date: consent.granted_at.slice(0, 10) })}</Note>
            <Button label={t("share.webRevoke")} onPress={() => void revoke(consent)} small danger disabled={busy} />
          </div>
        ))}
        {past.length > 0 && (
          <Note tone="muted">{t("share.webRevokedList", { names: past.map((consent) => consent.display_name).join(", ") })}</Note>
        )}
      </Card>
    </>
  );
}

const themeBody = "#3d4a5c";
