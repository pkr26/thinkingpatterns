/**
 * Patients: the therapist's consented patient list, the pairing-code
 * generator (how a new patient connects), and the honest empty/revoked
 * states. Selecting an active patient opens the pattern view.
 *
 * NEW-3 / F.4 (2026-09-22): the "Account security" panel surfaces the
 * backend's verifier-gated rotation routes (PUT /therapist/wrap-key,
 * PUT /account/credential) — password change, interrupted-change
 * recovery, and compromise rotation of the sharing key.
 */
import { useCallback, useEffect, useState } from "react";
import { api, auth, ApiError, type AccessLogRow, type Patient } from "../api";
import {
  decryptCaseloadSummary,
  decryptInsights,
  deriveMasterKey,
  derivePortalKeys,
  fromBase64,
  generateTherapistKeyPair,
  keyFingerprint,
  openSealedPrivateKey,
  sealPrivateKeyForUpload,
  toBase64,
  unwrapPatientDataKey,
} from "../crypto";
import type { Bytes, CaseloadSummary } from "../crypto";
import { currentOrigin, randomBytes, visitAnchorStore } from "../platform";
import { Button, Card, ErrorBanner, Field, Note, theme } from "../ui";
import { normalizeBaseUrl, passwordPolicyError } from "./LoginView";
import type { PortalSession } from "./PatientView";

const dayOf = (iso: string): string => iso.slice(0, 10);

/** Per-patient caseload triage summary (2026-09-17): pattern count,
 *  sensitive-card presence, and new-since-reviewed — derived by fetching
 *  and decrypting each active patient's insights sequentially (the read
 *  rate limits are per-account and sequential is the polite shape). */
export interface CaseloadScanRow {
  userId: string;
  patterns: number;
  sensitive: boolean;
  newSinceReviewed: number;
  lastReviewed: string | null;
}

/** The full password-derived key set, held only for the duration of one
 * Account-security action and zeroized the moment it ends (the LoginView
 * wipeKeys idiom — audit P-1: the verifier never outlives its send). */
type PortalKeySet = Awaited<ReturnType<typeof derivePortalKeys>>;

export function PatientsView(props: {
  onOpen: (patient: Patient) => void;
  onSignOut: () => void;
  /** NEW-3 / F.4 (2026-09-22): fired after a successful password change —
   *  the credential rotation killed every bearer (including this one), so
   *  App locks the whole session down with the "all sessions ended"
   *  notice. Falls back to the plain sign-out path when not supplied. */
  onSessionsEnded?: () => void;
  displayName: string;
  session?: PortalSession;
}): React.JSX.Element {
  const [patients, setPatients] = useState<Patient[]>([]);
  const [pairingCode, setPairingCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  /** Audit fix 17 (2026-09-21): the patients-load failure (not pairing-code
   *  or scan errors) offers an in-page retry of the fetch. */
  const [loadFailed, setLoadFailed] = useState(false);
  /** F-6 (2026-09-21): the list used to flash "No patients are sharing
   *  with you yet." before the FIRST fetch resolved. */
  const [loaded, setLoaded] = useState(false);
  /** F-6 (2026-09-21): search + ordering for the active list. */
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<"shared" | "username" | "triage">("shared");
  const [scan, setScan] = useState<Record<string, CaseloadScanRow> | null>(null);
  const [scanning, setScanning] = useState(false);
  /** This therapist's own wrap-key fingerprint (shown beside the pairing
   * code so the patient can verify it after lookup — 2026-09-17 audit). */
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  /** Audit B-4 (2026-09-21): the accountability view of this therapist's
   *  own portal actions, fetched on demand from the server's access log. */
  const [auditRows, setAuditRows] = useState<AccessLogRow[] | null>(null);
  const [auditBusy, setAuditBusy] = useState(false);
  const [auditError, setAuditError] = useState("");

  // --- Account security (NEW-3 / F.4, 2026-09-22) -----------------------------
  // Collapsed by default like the access-history panel above: nothing is
  // derived, fetched, or sent until the therapist asks for it.
  const [securityOpen, setSecurityOpen] = useState(false);
  const [secBusy, setSecBusy] = useState(false);
  const [secError, setSecError] = useState("");
  const [secNotice, setSecNotice] = useState("");
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [recCurrent, setRecCurrent] = useState("");
  const [recIntended, setRecIntended] = useState("");
  const [compCurrent, setCompCurrent] = useState("");
  const [compConfirmed, setCompConfirmed] = useState(false);
  /** The fresh salt of a password change whose wrap-key PUT landed but
   *  whose credential PUT failed — the interrupted-change window. The
   *  stored blob is sealed under (intended-new password + THIS salt), so
   *  the salt is the only thing that makes the intended-new KEK
   *  re-derivable and the account repairable. Memory only: a page reload
   *  forfeits recovery, exactly like the no-recovery warning at
   *  registration (audit F-4). */
  const [interruptedSaltB64, setInterruptedSaltB64] = useState<string | null>(null);
  // --- Optional TOTP second factor (2026-09-21 audit C-2/F-4, 2026-09-22) ---
  // totpStatus: null = not yet asked, then the server's answer via /me
  // once the panel opens. totpPending holds the setup response — the
  // secret is shown exactly once, until confirmed or the panel closes.
  const [totpStatus, setTotpStatus] = useState<boolean | null>(null);
  const [totpPending, setTotpPending] = useState<{ secretBase32: string; otpauthUri: string } | null>(null);
  const [totpPw, setTotpPw] = useState("");
  const [totpCode, setTotpCode] = useState("");

  /** Same derivation as the sign-in path, with the same P-1 hygiene: the
   *  salt bytes and master never outlive this function; only the returned
   *  zeroizable subkey arrays do. */
  const deriveFor = async (password: string, saltB64: string): Promise<PortalKeySet> => {
    const saltBytes = fromBase64(saltB64);
    let master: Awaited<ReturnType<typeof deriveMasterKey>> | null = null;
    try {
      master = await deriveMasterKey(password, saltBytes);
      return await derivePortalKeys(master);
    } finally {
      saltBytes.fill(0);
      master?.fill(0);
    }
  };

  const wipeKeySet = (...sets: Array<PortalKeySet | null | undefined>): void => {
    for (const set of sets) {
      set?.authKey.fill(0);
      set?.wrapKek.fill(0);
      set?.noteKey.fill(0);
    }
  };

  /** The FINAL credential PUT is the one request whose failure strands the
   *  account in the re-wrapped window, so transient faults get up to three
   *  retries — network-unreachable (status 0) and 5xx only. A 403 is the
   *  server rejecting the current verifier: retrying it is pointless and
   *  burns the shared auth rate limit. */
  const putCredentialWithRetry = async (
    verifierB64: string,
    newSaltB64: string,
    newVerifierB64: string,
  ): Promise<void> => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        await api.rotateCredential(verifierB64, newSaltB64, newVerifierB64);
        return;
      } catch (err) {
        const status = err instanceof ApiError ? err.status : -1;
        if (attempt >= 3 || (status !== 0 && status < 500)) throw err;
      }
    }
  };

  const changePassword = async () => {
    if (secBusy || !props.session) return;
    if (pwNew !== pwConfirm) {
      setSecError("the two new passwords do not match");
      return;
    }
    // Same policy the registration form enforces (F-4 register copy).
    const policy = passwordPolicyError(pwNew);
    if (policy) {
      setSecError(policy);
      return;
    }
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    let currentKeys: PortalKeySet | null = null;
    let newKeys: PortalKeySet | null = null;
    let pkcs8: Bytes | null = null;
    try {
      const base = normalizeBaseUrl(currentOrigin());
      if (!base) throw new Error("this portal must be served from its configured secure origin");
      const username = props.session.username;
      const { salt } = await auth.saltFor(base, username);
      currentKeys = await deriveFor(pwCurrent, salt);
      // P-1: the verifier string is derived here, at the send, from the
      // raw bytes — which are wiped the moment the string exists.
      const verifierB64 = toBase64(currentKeys.authKey);
      currentKeys.authKey.fill(0);
      // F-6: through the platform seam; exactly the register payload's
      // 16-byte salt shape.
      const newSaltBytes = randomBytes(16);
      const newSaltB64 = toBase64(newSaltBytes);
      try {
        newKeys = await deriveFor(pwNew, newSaltB64);
      } finally {
        newSaltBytes.fill(0);
      }
      const newVerifierB64 = toBase64(newKeys.authKey);
      newKeys.authKey.fill(0);
      const me = await api.me();
      // Ordering contract (backend rotate_wrap_key docstring): re-wrap the
      // SAME private key under the NEW password's KEK FIRST, while both
      // passwords are derivable, THEN rotate the login credential.
      pkcs8 = await openSealedPrivateKey(currentKeys.wrapKek, me.wrap_key_blob, username);
      if (!pkcs8) {
        throw new Error("the current password did not unlock your stored sharing key — nothing was changed");
      }
      const resealedBlob = await sealPrivateKeyForUpload(newKeys.wrapKek, pkcs8, username);
      await api.rotateWrapKey(verifierB64, me.wrap_pub_key, resealedBlob);
      try {
        await putCredentialWithRetry(verifierB64, newSaltB64, newVerifierB64);
      } catch (err) {
        // The interrupted-change window: the blob is now sealed under the
        // NEW password while the sign-in credential is unchanged. Retain
        // the new salt so the recovery form below can re-derive the
        // intended-new KEK — the only state that keeps the account
        // repairable (see interruptedSaltB64).
        setInterruptedSaltB64(newSaltB64);
        throw new Error(
          `the password change did not complete (${err instanceof Error ? err.message : "credential rotation failed"}) — `
            + "your sharing key is now wrapped under the NEW password while your sign-in password is unchanged. "
            + "Recover it with “Recover sharing key” below BEFORE leaving this page.",
        );
      }
      // Success: the server bumped the token epoch — every bearer,
      // including this session's, is dead. Lock down through the same
      // path as sign-out so no key material outlives the credential.
      setSecNotice("Password changed. Every session — including this one — has ended; sign in with your new password.");
      if (props.onSessionsEnded) props.onSessionsEnded();
      else props.onSignOut();
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not change the password");
    } finally {
      wipeKeySet(currentKeys, newKeys);
      pkcs8?.fill(0);
      // Password strings cannot be overwritten in JavaScript; dropping
      // them from the live form promptly is the available hygiene.
      setPwCurrent("");
      setPwNew("");
      setPwConfirm("");
      setSecBusy(false);
    }
  };

  const recoverSharingKey = async () => {
    if (secBusy || !props.session || !interruptedSaltB64) return;
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    let currentKeys: PortalKeySet | null = null;
    let intendedKeys: PortalKeySet | null = null;
    let pkcs8: Bytes | null = null;
    try {
      const base = normalizeBaseUrl(currentOrigin());
      if (!base) throw new Error("this portal must be served from its configured secure origin");
      const username = props.session.username;
      const { salt } = await auth.saltFor(base, username);
      currentKeys = await deriveFor(recCurrent, salt);
      const verifierB64 = toBase64(currentKeys.authKey);
      currentKeys.authKey.fill(0);
      intendedKeys = await deriveFor(recIntended, interruptedSaltB64);
      const me = await api.me();
      pkcs8 = await openSealedPrivateKey(intendedKeys.wrapKek, me.wrap_key_blob, username);
      if (!pkcs8) {
        throw new Error("the second password did not unlock the stored sharing key — nothing was changed; check the password you were changing to");
      }
      const resealedBlob = await sealPrivateKeyForUpload(currentKeys.wrapKek, pkcs8, username);
      await api.rotateWrapKey(verifierB64, me.wrap_pub_key, resealedBlob);
      setInterruptedSaltB64(null);
      setSecNotice("Sharing key recovered — it is sealed under your current sign-in password again. Your sign-in password never changed; you can retry the password change.");
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not recover the sharing key");
    } finally {
      wipeKeySet(currentKeys, intendedKeys);
      pkcs8?.fill(0);
      setRecCurrent("");
      setRecIntended("");
      setSecBusy(false);
    }
  };

  const rotateSharingKey = async () => {
    if (secBusy || !props.session || !compConfirmed) return;
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    let currentKeys: PortalKeySet | null = null;
    try {
      const base = normalizeBaseUrl(currentOrigin());
      if (!base) throw new Error("this portal must be served from its configured secure origin");
      const username = props.session.username;
      const { salt } = await auth.saltFor(base, username);
      currentKeys = await deriveFor(compCurrent, salt);
      const verifierB64 = toBase64(currentKeys.authKey);
      currentKeys.authKey.fill(0);
      // A genuinely FRESH keypair sealed under the CURRENT password's KEK
      // — nothing derived from the possibly-compromised old key is reused.
      const pair = await generateTherapistKeyPair(currentKeys.wrapKek, username);
      await api.rotateWrapKey(verifierB64, pair.publicKeySpkiB64, pair.wrapKeyBlobB64);
      setSecNotice(
        "Sharing key rotated. Existing grants stay readable only after each patient re-wraps their data key via the pairing fingerprint path; grants that never re-wrap are intentionally lost — retiring the compromised key is the point. Until you sign out, this tab still holds the old key in memory, so not-yet-re-wrapped grants may keep opening here.",
      );
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not rotate the sharing key");
    } finally {
      wipeKeySet(currentKeys);
      setCompCurrent("");
      setCompConfirmed(false);
      setSecBusy(false);
    }
  };

  // --- Optional TOTP second factor (2026-09-22) ---------------------------------
  // Every action is verifier-gated server-side; locally the same P-1
  // hygiene as the flows above: derive, send the b64 verifier once, wipe.

  /** Derive the login verifier from the just-typed password (never from
   *  anything cached — the whole point is proving password knowledge). */
  const totpVerifierFor = async (): Promise<string> => {
    if (!props.session) throw new Error("not signed in");
    const base = normalizeBaseUrl(currentOrigin());
    if (!base) throw new Error("this portal must be served from its configured secure origin");
    const { salt } = await auth.saltFor(base, props.session.username);
    const keys = await deriveFor(totpPw, salt);
    const verifierB64 = toBase64(keys.authKey);
    wipeKeySet(keys);
    return verifierB64;
  };

  const totpStart = async () => {
    if (secBusy || !props.session || !totpPw) return;
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    try {
      const verifier = await totpVerifierFor();
      const setup = await api.totpSetup(verifier);
      setTotpPending({ secretBase32: setup.secret_base32, otpauthUri: setup.otpauth_uri });
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not start two-factor setup");
    } finally {
      setTotpPw("");
      setTotpCode("");
      setSecBusy(false);
    }
  };

  const totpEnableConfirm = async () => {
    if (secBusy || !props.session || !totpPending || !totpPw || !/^\d{6}$/.test(totpCode)) return;
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    try {
      const verifier = await totpVerifierFor();
      await api.totpEnable(verifier, totpCode);
      setTotpStatus(true);
      setTotpPending(null);
      setSecNotice(
        "Two-factor authentication is on: sign-in now asks for a 6-digit code from your authenticator. Keep a backup of the secret somewhere safe — a lost authenticator needs an operator to clear.",
      );
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not enable two-factor");
    } finally {
      setTotpPw("");
      setTotpCode("");
      setSecBusy(false);
    }
  };

  const totpDisableConfirm = async () => {
    if (secBusy || !props.session || !totpPw || !/^\d{6}$/.test(totpCode)) return;
    setSecBusy(true);
    setSecError("");
    setSecNotice("");
    try {
      const verifier = await totpVerifierFor();
      await api.totpDisable(verifier, totpCode);
      setTotpStatus(false);
      setSecNotice("Two-factor authentication is off. Sign-in is password-only again.");
    } catch (err) {
      setSecError(err instanceof Error ? err.message : "could not disable two-factor");
    } finally {
      setTotpPw("");
      setTotpCode("");
      setSecBusy(false);
    }
  };

  // Ask the server for the honest state the first time the panel opens
  // (the collapsed panel derives and sends nothing).
  useEffect(() => {
    if (!securityOpen || totpStatus !== null || !props.session) return;
    let cancelled = false;
    api.me()
      .then((me) => { if (!cancelled) setTotpStatus(me.totp_enabled === true); })
      .catch(() => { if (!cancelled) setTotpStatus(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [securityOpen, props.session]);

  const loadAudit = useCallback(() => {
    setAuditError("");
    setAuditBusy(true);
    api.accessLog()
      .then(setAuditRows)
      .catch(() => { setAuditError("could not load the access history"); })
      .finally(() => { setAuditBusy(false); });
  }, []);

  useEffect(() => {
    if (!props.session) return;
    let cancelled = false;
    keyFingerprint(props.session.publicKeyB64)
      .then((fp) => { if (!cancelled) setFingerprint(fp); })
      .catch(() => { if (!cancelled) setFingerprint(null); });
    return () => { cancelled = true; };
  }, [props.session]);

  const refresh = useCallback(() => {
    setError("");
    setLoadFailed(false);
    api.patients()
      .then((rows) => {
        setPatients(rows);
        setLoaded(true);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "could not load patients");
        setLoadFailed(true);
      });
  }, []);
  useEffect(refresh, [refresh]);

  // Caseload summaries (2026-09-19): the server writes a small ECIS-wrapped
  // summary per active consent at each patient recompute. Decrypting them
  // here makes triage O(1) per patient (no full insight fetches) and — the
  // safety point — surfaces a sensitive card's PRESENCE without opening
  // every chart. Failures degrade to "no summary": the row renders "—"
  // and the manual scan below remains the fallback.
  const [summaries, setSummaries] = useState<Record<string, CaseloadSummary | null>>({});
  useEffect(() => {
    if (!props.session || patients.length === 0) return;
    let cancelled = false;
    void (async () => {
      const next: Record<string, CaseloadSummary | null> = {};
      for (const patient of patients) {
        if (patient.status !== "active" || !patient.summary_blob || !patient.summary_eph_pub) {
          continue;
        }
        next[patient.user_id] = await decryptCaseloadSummary(
          props.session!.privateKey,
          props.session!.publicKeyB64,
          patient.summary_eph_pub,
          patient.summary_blob,
          patient.user_id,
          props.session!.userId,
        );
      }
      if (!cancelled) setSummaries(next);
    })();
    return () => { cancelled = true; };
  }, [props.session, patients]);

  /** F-6 (2026-09-21) + audit round 2 F-8: the sensitive-caseload banner
   *  folds in the manual scan rows — a SUCCESSFUL scan (patterns >= 0)
   *  outranks the server summary for the rest of the session; a FAILED
   *  scan (patterns === -1) proves nothing and falls back to the summary,
   *  matching the per-row count display below. Scan rows carry no
   *  scan-time timestamp, so precedence is positional (the scan ran this
   *  session, after the summary's as-of date), not clock-compared. */
  const sensitiveCount = Array.from(
    new Set([...Object.keys(summaries), ...Object.keys(scan ?? {})]),
  ).filter((uid) => {
    const row = scan?.[uid];
    if (row && row.patterns >= 0) return row.sensitive === true;
    return summaries[uid]?.sensitive === true;
  }).length;

  const newCode = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    setPairingCode(null);
    try {
      const { code } = await api.newPairingCode();
      setPairingCode(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not create a pairing code");
    } finally {
      setBusy(false);
    }
  };

  const scanCaseload = async () => {
    if (scanning || !props.session) return;
    setScanning(true);
    setError("");
    const rows: Record<string, CaseloadScanRow> = {};
    try {
      for (const patient of patients.filter((p) => p.status === "active")) {
        try {
          const summary = await api.patientInsights(patient.user_id);
          // Same L-75 anchor store the chart uses (sessionStorage first,
          // lock-scrubbed localStorage fallback): the scan and the chart
          // must agree on which stamp the delta counts from.
          const stamp = visitAnchorStore.get(`mindpattern.lastVisit.${props.session.userId}.${patient.user_id}`);
          const row: CaseloadScanRow = {
            userId: patient.user_id,
            patterns: 0,
            sensitive: false,
            newSinceReviewed: 0,
            lastReviewed: stamp ? dayOf(stamp) : null,
          };
          if (summary.blob && summary.phase === "insight" && patient.ephemeral_pub && patient.wrapped_key) {
            // Keep the concrete ArrayBuffer-backed crypto type. A generic
            // Uint8Array could include SharedArrayBuffer storage, which the
            // WebCrypto helper intentionally rejects.
            let dataKey: Bytes | null = null;
            try {
              dataKey = await unwrapPatientDataKey(
                props.session.privateKey,
                patient.ephemeral_pub,
                patient.wrapped_key,
                patient.user_id,
                props.session.userId,
                props.session.publicKeyB64,
              );
              const payload = await decryptInsights(dataKey, patient.user_id, summary.blob);
              const surfaced = payload.stats.patterns ?? [];
              row.patterns = surfaced.length;
              row.sensitive = surfaced.some((p) => p.detail.sensitive === true);
              row.newSinceReviewed = stamp
                ? surfaced.filter((p) => p.detail.first_seen && p.detail.first_seen > stamp).length
                : surfaced.length;
            } finally {
              // Caseload scans unwrap each patient's data key in turn. It is
              // needed only for this one decrypt; retain no raw key bytes
              // after either a successful scan or a decrypt failure.
              dataKey?.fill(0);
            }
          }
          rows[patient.user_id] = row;
        } catch {
          rows[patient.user_id] = {
            userId: patient.user_id, patterns: -1, sensitive: false,
            newSinceReviewed: -1, lastReviewed: null,
          }; // -1 = could not scan (revoked mid-scan, dead key): honest blank
        }
      }
      setScan(rows);
    } finally {
      setScanning(false);
    }
  };

  const activeAll = patients.filter((p) => p.status === "active");
  // F-6 (2026-09-21): search + sort. Triage ordering (sensitive first,
  // then most-new-since-reviewed, per the freshest scan row) only applies
  // after a scan — otherwise newest share first.
  const needle = search.trim().toLowerCase();
  const active = activeAll
    .filter((p) => !needle || p.username.toLowerCase().includes(needle))
    .sort((a, b) => {
      if (sort === "username") return a.username.localeCompare(b.username);
      if (sort === "triage" && scan) {
        const rowA = scan[a.user_id];
        const rowB = scan[b.user_id];
        const sensA = rowA?.sensitive === true ? 1 : 0;
        const sensB = rowB?.sensitive === true ? 1 : 0;
        if (sensA !== sensB) return sensB - sensA;
        const newA = rowA?.newSinceReviewed ?? -1;
        const newB = rowB?.newSinceReviewed ?? -1;
        if (newA !== newB) return newB - newA;
      }
      return dayOf(b.granted_at).localeCompare(dayOf(a.granted_at));
    });
  const stopped = patients.filter((p) => p.status !== "active");

  return (
    <main style={{ backgroundColor: theme.bg, minHeight: "100vh", color: theme.body, padding: 24, maxWidth: 860, margin: "0 auto" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 18 }}>
        <h1 style={{ color: theme.text, fontSize: 20, margin: 0 }}>Patients — {props.displayName}</h1>
        <Button label="Sign out" small onPress={props.onSignOut} />
      </header>

      <Card title="Connect a new patient">
        <Note>
          Generate a pairing code and read it to your patient. They enter it in their app, see your
          name, and confirm with their password. The code works once and expires in 15 minutes.
        </Note>
        {pairingCode && (
          <p data-testid="pairing-code" style={{ margin: 0, color: theme.text, fontSize: 28, letterSpacing: 6, fontWeight: 700 }}>
            {pairingCode}
          </p>
        )}
        {fingerprint && (
          <p data-testid="key-fingerprint" style={{ margin: "2px 0 0", color: theme.text, fontSize: 15, letterSpacing: 2, fontWeight: 600 }}>
            {fingerprint}
          </p>
        )}
        {fingerprint && (
          <Note>Your key fingerprint — ask your patient to read theirs back after they look you up; a mismatch means a key was substituted in transit.</Note>
        )}
        <Button label={busy ? "Generating…" : "Generate pairing code"} onPress={newCode} disabled={busy} />
      </Card>

      <ErrorBanner message={error} />
      {loadFailed && (
        // Audit fix 17 (2026-09-21): recovery from a failed caseload load
        // used to require a reload or sign-out.
        <div style={{ marginTop: 8 }}>
          <Button label="Retry loading patients" small onPress={refresh} />
        </div>
      )}

      {sensitiveCount > 0 && (
        <div data-testid="sensitive-banner" style={{ marginBottom: 14 }}>
          <Note tone="warn">
            {sensitiveCount} of your patients {sensitiveCount === 1 ? "has a sensitive card" : "have sensitive cards"} in
            their current patterns. Opening {sensitiveCount === 1 ? "that chart" : "those charts"} puts the
            non-quoting card first — the wording itself is never echoed here.
          </Note>
        </div>
      )}

      <h3 style={{ color: theme.muted, fontSize: 13, letterSpacing: 1, marginTop: 22 }}>ACTIVE</h3>
      {activeAll.length > 1 && (
        <div style={{ marginBottom: 10, display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <Button label={scanning ? "Scanning caseload…" : "Scan caseload for triage"} small onPress={() => void scanCaseload()} disabled={scanning} />
          {/* F-6 (2026-09-21): search + sort for the caseload. */}
          <label style={{ color: theme.muted, fontSize: 12 }}>
            search{" "}
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="username…"
              aria-label="Search patients by username"
              style={{
                backgroundColor: theme.cardDeep,
                color: theme.text,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius,
                padding: "6px 10px",
                fontSize: 13,
                fontFamily: "inherit",
              }}
            />
          </label>
          <label style={{ color: theme.muted, fontSize: 12 }}>
            sort{" "}
            <select
              value={sort}
              onChange={(e) => setSort(e.target.value as typeof sort)}
              aria-label="Sort patients"
              style={{
                backgroundColor: theme.cardDeep,
                color: theme.text,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius,
                padding: "4px 6px",
                fontSize: 13,
              }}
            >
              <option value="shared">newest share</option>
              <option value="username">username</option>
              <option value="triage">triage{scan ? "" : " (scan first)"}</option>
            </select>
          </label>
        </div>
      )}
      {activeAll.length > 1 && (
        <div style={{ marginBottom: 10 }}>
          <span style={{ color: theme.muted, fontSize: 12 }}>
            The triage scan fetches each patient's decrypted pattern counts sequentially — nothing is stored.
          </span>
        </div>
      )}
      {/* F-6 (2026-09-21): no empty-state flash before the first fetch. */}
      {!loaded && !loadFailed && <Note>Loading your caseload…</Note>}
      {loaded && activeAll.length === 0 && <Note>No patients are sharing with you yet.</Note>}
      {loaded && activeAll.length > 0 && active.length === 0 && (
        <Note>No patients match “{search.trim()}”.</Note>
      )}
      {active.map((patient) => {
        const row = scan?.[patient.user_id];
        const summary = summaries[patient.user_id];
        return (
        <Card key={patient.user_id}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
            <div>
              <strong style={{ color: theme.text, fontSize: 15 }}>{patient.username}</strong>
              <Note>
                sharing since {dayOf(patient.granted_at)}
                {/* M-21 (2026-09-20): a manual scan row is FRESHER than the
                    server's last-recompute summary, so it wins when both
                    exist; the summary count otherwise renders with its
                    as-of date (forDate), because "4 patterns" is only
                    interpretable next to the date it was true of. */}
                {row && row.patterns >= 0 && ` · ${row.patterns} pattern${row.patterns === 1 ? "" : "s"} (scanned just now)`}
                {(!row || row.patterns < 0) && summary && ` · ${summary.patterns} pattern${summary.patterns === 1 ? "" : "s"} as of ${summary.forDate ?? "an unknown date"}`}
                {row && row.newSinceReviewed > 0 && ` · ${row.newSinceReviewed} new`}
                {row && row.lastReviewed && ` · reviewed ${row.lastReviewed}`}
              </Note>
              {(row?.sensitive || summary?.sensitive) && (
                <Note tone="warn">a sensitive card is present — review ordering puts it first</Note>
              )}
            </div>
            <Button label="Open patterns" onPress={() => props.onOpen(patient)} />
          </div>
        </Card>
        );
      })}

      {stopped.length > 0 && (
        <>
          <h3 style={{ color: theme.muted, fontSize: 13, letterSpacing: 1, marginTop: 22 }}>STOPPED SHARING</h3>
          {stopped.map((patient) => (
            <Card key={patient.user_id} deep>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
                <div>
                  <strong style={{ color: theme.text, fontSize: 14 }}>{patient.username}</strong>
                  <Note>
                    access ended {patient.revoked_at ? dayOf(patient.revoked_at) : "recently"} — their
                    entries and patterns are no longer reachable. Your notes about this patient stay.
                  </Note>
                </div>
                {/* M-22 (2026-09-20): the copy above promises the notes stay,
                    but nothing could reach them. The chart opens in its
                    notes-only mode for stopped consents (the server permits
                    note access at any consent status). */}
                <Button label="Open my notes" small onPress={() => props.onOpen(patient)} />
              </div>
            </Card>
          ))}
        </>
      )}
      {/* Audit B-4 (2026-09-21): the audit trail used to be write-only —
          neither party could read who accessed what. This is the
          therapist-side accountability view; patients have their own
          who-accessed-my-data endpoint on the mobile side. */}
      <Card title="My access history" deep>
        {auditRows === null ? (
          <div>
            <Button
              label={auditBusy ? "Loading…" : "Load access history"}
              small
              onPress={loadAudit}
              disabled={auditBusy}
            />
            <span style={{ color: theme.muted, fontSize: 12, marginLeft: 10 }}>
              Every read and write this portal performed (newest 100) — nothing is loaded until you ask.
            </span>
          </div>
        ) : auditRows.length === 0 ? (
          <Note>No recorded actions yet.</Note>
        ) : (
          auditRows.map((row, index) => (
            <Note key={`${row.at}-${index}`}>
              {new Date(row.at).toLocaleString()} — {row.action.replaceAll("_", " ")}
              {row.patient_name ? ` — ${row.patient_name}` : ""}
            </Note>
          ))
        )}
        {auditError && (
          <Note tone="danger" role="status">
            {auditError}
          </Note>
        )}
      </Card>

      {/* NEW-3 / F.4 (2026-09-22): the backend's verifier-gated rotation
          routes existed and were tested server-side, but no portal surface
          reached them — a therapist could not change a password, repair an
          interrupted change, or retire a compromised sharing key. Collapsed
          by default like the access-history panel: nothing is derived,
          fetched, or sent until asked for. */}
      <Card title="Account security" deep>
        {!securityOpen ? (
          <div>
            <Button label="Show account security" small onPress={() => setSecurityOpen(true)} />
            <span style={{ color: theme.muted, fontSize: 12, marginLeft: 10 }}>
              Change your password, recover your sharing key after an interrupted change, or rotate a
              compromised sharing key — nothing runs until you ask.
            </span>
          </div>
        ) : (
          <>
            <div>
              <strong style={{ color: theme.text, fontSize: 13 }}>Change password</strong>
              <Note>
                Your sharing key is re-wrapped under the new password first, then the login credential is
                rotated — on success every session, including this one, is signed out. There is still no
                password reset: keep the new password in a password manager.
              </Note>
              <Field label="Current password" value={pwCurrent} onChange={setPwCurrent} type="password" autoComplete="current-password" />
              <Field label="New password" value={pwNew} onChange={setPwNew} type="password" autoComplete="new-password" />
              <Field label="Repeat new password" value={pwConfirm} onChange={setPwConfirm} type="password" autoComplete="new-password" />
              <Button
                label={secBusy ? "Changing…" : "Change password"}
                small
                onPress={() => void changePassword()}
                disabled={secBusy || !props.session || !pwCurrent || !pwNew || !pwConfirm}
              />
            </div>
            <div style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 10 }}>
              <strong style={{ color: theme.text, fontSize: 13 }}>Recover sharing key</strong>
              <Note>
                Repairs an interrupted password change: if the change failed after the sharing key was
                re-wrapped, this seals the same key back under the password you actually sign in with, so
                the account opens normally again.
              </Note>
              {interruptedSaltB64 ? (
                <Note tone="warn">
                  An interrupted change from this tab is repairable right now — do it before closing or
                  reloading this page.
                </Note>
              ) : (
                <Note>
                  No interrupted change is remembered in this tab. After a reload the re-wrapped key is
                  not recoverable — an account with no recovery path stays that way (audit F-4).
                </Note>
              )}
              <Field label="Current password (the one you sign in with)" value={recCurrent} onChange={setRecCurrent} type="password" autoComplete="current-password" />
              <Field label="The password you were changing to" value={recIntended} onChange={setRecIntended} type="password" autoComplete="off" />
              <Button
                label={secBusy ? "Recovering…" : "Recover sharing key"}
                small
                onPress={() => void recoverSharingKey()}
                disabled={secBusy || !props.session || !interruptedSaltB64 || !recCurrent || !recIntended}
              />
            </div>
            <div style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 10 }}>
              <strong style={{ color: theme.text, fontSize: 13 }}>Rotate sharing key (suspected compromise)</strong>
              <Note>
                Publishes a brand-new sharing keypair sealed under your current password. Existing grants
                stay readable only after each patient re-wraps their data key via the pairing fingerprint
                path; grants that never re-wrap are intentionally lost — retiring the compromised key is
                the point. Your notes are unaffected: they are sealed under your password, not this key.
              </Note>
              <Field label="Current password (to authorize rotation)" value={compCurrent} onChange={setCompCurrent} type="password" autoComplete="current-password" />
              <label style={{ display: "flex", gap: 8, alignItems: "flex-start", color: theme.muted, fontSize: 12 }}>
                <input
                  type="checkbox"
                  checked={compConfirmed}
                  onChange={(e) => setCompConfirmed(e.target.checked)}
                  aria-label="Confirm sharing-key rotation"
                />
                I understand that grants from patients who never re-wrap are intentionally lost.
              </label>
              <Button
                label={secBusy ? "Rotating…" : "Rotate sharing key"}
                small
                danger
                onPress={() => void rotateSharingKey()}
                disabled={secBusy || !props.session || !compConfirmed || !compCurrent}
              />
            </div>
            <div style={{ borderTop: `1px solid ${theme.border}`, paddingTop: 10 }}>
              <strong style={{ color: theme.text, fontSize: 13 }}>Two-factor authentication (authenticator app)</strong>
              {totpStatus === null && (
                <Note role="status">Checking this account&apos;s two-factor status…</Note>
              )}
              {totpStatus === false && !totpPending && (
                <>
                  <Note>
                    Optional second factor for sign-in: after it is enabled, your password AND a 6-digit
                    code from an authenticator app are both required. Disabling it later needs both
                    halves again — and a lost authenticator has no self-service recovery (operator
                    action only), matching this portal&apos;s no-recovery design.
                  </Note>
                  <Field label="Current password (to authorize setup)" value={totpPw} onChange={setTotpPw} type="password" autoComplete="current-password" />
                  <Button
                    label={secBusy ? "Starting…" : "Set up authenticator"}
                    small
                    onPress={() => void totpStart()}
                    disabled={secBusy || !props.session || !totpPw}
                  />
                </>
              )}
              {totpPending && (
                <>
                  <Note tone="warn">
                    Enter this secret in your authenticator app NOW — it is shown exactly once and
                    never again. Two-factor only takes effect after you confirm a code below.
                  </Note>
                  <p
                    aria-label="Authenticator secret (manual entry)"
                    style={{ fontFamily: "monospace", color: theme.text, fontSize: 14, wordBreak: "break-all", margin: 0, letterSpacing: 1 }}
                  >
                    {totpPending.secretBase32}
                  </p>
                  <p
                    aria-label="otpauth URI for apps that accept it"
                    style={{ fontFamily: "monospace", color: theme.muted, fontSize: 11, wordBreak: "break-all", margin: 0 }}
                  >
                    {totpPending.otpauthUri}
                  </p>
                  <Field label="Current password (to authorize setup)" value={totpPw} onChange={setTotpPw} type="password" autoComplete="current-password" />
                  <Field
                    label="6-digit code from the app"
                    value={totpCode}
                    onChange={(value) => setTotpCode(value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="123456"
                    autoComplete="one-time-code"
                  />
                  <Button
                    label={secBusy ? "Enabling…" : "Enable two-factor"}
                    small
                    onPress={() => void totpEnableConfirm()}
                    disabled={secBusy || !props.session || !totpPw || !/^\d{6}$/.test(totpCode)}
                  />
                </>
              )}
              {totpStatus === true && (
                <>
                  <Note tone="ok" role="status">
                    Enabled — sign-in requires your password and a current 6-digit code.
                  </Note>
                  <Note tone="danger">
                    Turning two-factor off needs your password AND a current code. If the authenticator
                    is lost, only an operator can clear it — there is no self-service recovery.
                  </Note>
                  <Field label="Current password (to disable two-factor)" value={totpPw} onChange={setTotpPw} type="password" autoComplete="current-password" />
                  <Field
                    label="6-digit code (to disable two-factor)"
                    value={totpCode}
                    onChange={(value) => setTotpCode(value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="123456"
                    autoComplete="one-time-code"
                  />
                  <Button
                    label={secBusy ? "Disabling…" : "Disable two-factor"}
                    small
                    danger
                    onPress={() => void totpDisableConfirm()}
                    disabled={secBusy || !props.session || !totpPw || !/^\d{6}$/.test(totpCode)}
                  />
                </>
              )}
            </div>
            <Button
              label="Hide account security"
              small
              onPress={() => {
                setSecurityOpen(false);
                // The pending secret is shown-once material: closing the
                // panel discards it (a fresh setup mints a fresh secret).
                setTotpPending(null);
                setTotpPw("");
                setTotpCode("");
              }}
              disabled={secBusy}
            />
          </>
        )}
        <ErrorBanner message={secError} />
        {secNotice && (
          <Note tone="ok" role="status">
            {secNotice}
          </Note>
        )}
      </Card>
    </main>
  );
}
