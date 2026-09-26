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
      setError("Your session locked — sign in again.");
      return;
    }
    try {
      const rows = await api.listConsents();
      if (generation.current !== run) return;
      setConsents(rows);
    } catch (err) {
      if (generation.current !== run) return;
      setError(err instanceof Error ? err.message : "Could not load sharing.");
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
      setError("Type the pairing code your therapist shows.");
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
      if (err instanceof ApiError && err.status === 404) setError("That code is not valid — codes expire after 15 minutes and work once.");
      else setError(err instanceof Error ? err.message : "Lookup failed.");
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
      setStatus(`Shared with ${lookup.name}. They can now see your patterns and the entries behind them, until you revoke.`);
      setCode("");
      setLookup(null);
      setDisclosureAccepted(false);
      setFingerprintVerified(false);
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.code === "disclosure_outdated") {
        setError("The sharing terms changed — start the pairing again to see the current disclosure.");
      } else {
        setError(err instanceof Error ? err.message : "Could not complete sharing.");
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
      setStatus(`Revoked — ${consent.display_name} loses access immediately. What they already read cannot be unread.`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not revoke.");
    } finally {
      setBusy(false);
    }
  };

  const active = consents?.filter((consent) => consent.status === "active") ?? [];
  const past = consents?.filter((consent) => consent.status !== "active") ?? [];

  return (
    <>
      <Card title="Share with a therapist">
        <Note tone="muted">{"Zero-knowledge: your key is wrapped to your therapist's public key — the server never sees it, and neither does anyone else."}</Note>
        <Field label="Pairing code" value={code} onChange={setCode} placeholder="from your therapist's portal" />
        <Button label={busy ? "Working…" : "Look up"} onPress={() => void doLookup()} disabled={busy} small />
        {lookup && (
          <>
            <Note role="status">{`Therapist: ${lookup.name}`}</Note>
            <Note>{`Their key fingerprint: ${lookup.fingerprint}`}</Note>
            <Note tone="warn">{"Read this fingerprint back to your therapist (in the room or on the phone). If it does not match what their portal shows, STOP — a mismatch means the key was substituted."}</Note>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 13, color: themeBody }}>
              <input type="checkbox" checked={fingerprintVerified} onChange={(e) => setFingerprintVerified(e.target.checked)} />
              <span>
                {"We read the key fingerprint back to each other and it MATCHED. (A substituted key would decrypt nothing — but checking is the only proof the right therapist is on the other end.)"}
              </span>
            </label>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 13, color: themeBody }}>
              <input type="checkbox" checked={disclosureAccepted} onChange={(e) => setDisclosureAccepted(e.target.checked)} />
              <span>
                {"I understand: they can read my patterns and the decrypted entries behind them; every read is audit-logged; revoking ends access immediately but cannot unread what was already seen."}
              </span>
            </label>
            <Button label="Confirm and share" onPress={() => void grant()} disabled={busy || !disclosureAccepted || !fingerprintVerified} />
          </>
        )}
        <ErrorBanner message={error} />
        {status && <Note role="status" tone="ok">{status}</Note>}
      </Card>

      <Card title="Your grants">
        {consents === null && <Note role="status">Loading…</Note>}
        {consents !== null && active.length === 0 && <Note>No active grants — your journal is shared with no one.</Note>}
        {active.map((consent) => (
          <div key={consent.id} style={{ display: "flex", flexDirection: "column", gap: 6, borderTop: "1px solid #dfe5ec", paddingTop: 10 }}>
            <Note>{`${consent.display_name} (${consent.username}) — since ${consent.granted_at.slice(0, 10)}`}</Note>
            <Button label="Revoke access" onPress={() => void revoke(consent)} small danger disabled={busy} />
          </div>
        ))}
        {past.length > 0 && (
          <Note tone="muted">{`Revoked or ended: ${past.map((consent) => consent.display_name).join(", ")}.`}</Note>
        )}
      </Card>
    </>
  );
}

const themeBody = "#3d4a5c";
