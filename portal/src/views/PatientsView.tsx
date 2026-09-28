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
import { useCallback, useEffect, useRef, useState } from "react";
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
  serverWrapKeyFingerprint,
  toBase64,
  unwrapPatientDataKey,
} from "../crypto";
import type { Bytes, CaseloadSummary } from "../crypto";
import { copyToClipboard, currentOrigin, downloadTextFile, randomBytes, sessionStore, visitAnchorStore } from "../platform";
import { Button, Card, ErrorBanner, Field, Note } from "../ui";
import { normalizeBaseUrl, passwordPolicyError } from "./LoginView";
import { verifyInsightsGeneration, type PortalSession } from "./PatientView";

const dayOf = (iso: string): string => iso.slice(0, 10);

/** 2026-09-26 audit round (M, UX copy): the deep triage scan's access
 *  footprint — one insights fetch + full-blob decrypt per active patient,
 *  and one server audit row per patient — must be acknowledged once before
 *  the first run of a browser session. "Don't ask again" is deliberately
 *  MODULE state: it lives only as long as this tab's JS realm and never
 *  touches storage, so a fresh page load asks again. */
let scanConfirmedForSession = false;

/** Test seam: forget the session-scoped confirmation latch (the same
 *  shape as PatientView's resetInsightsFreshness). */
export function resetScanConfirmation(): void {
  scanConfirmedForSession = false;
}

/** independent audit 2026-09-27: the server-computed wrap-key fingerprint
 *  from the pairing-SAS response, accepted only in the exact shape the
 *  contract defines (16 lowercase hex chars — backend
 *  sharing.wrap_key_fingerprint). Absent/invalid → null → rendered as "no
 *  valid fingerprint" (never free-form), mirroring the mobile app's
 *  validServerFingerprint discipline. */
export function validServerFingerprint(value: string): string | null {
  return /^[0-9a-f]{16}$/.test(value) ? value : null;
}

/** S-4 (pentest 2026-09-26): the interrupted-change recovery salt, keyed by
 *  therapist. sessionStorage — never localStorage: the salt is the only
 *  material that makes an interrupted re-wrap repairable, and it must die
 *  with the browser session rather than persisting on a shared clinic
 *  machine. Degradation is the previous posture (memory only) where
 *  sessionStorage is locked away. */
const interruptedSaltKey = (userId: string): string =>
  `mindpattern.interruptedRotateSalt.${userId}`;

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
  /** 2026-09-26 audit round (M, UX copy): the armed state of the one-time
   *  scan confirmation (see scanConfirmedForSession above), plus its
   *  "don't ask again" checkbox. */
  const [confirmScan, setConfirmScan] = useState(false);
  const [scanNoAsk, setScanNoAsk] = useState(false);
  /** Generation token for the manual scan (2026-09-26 audit round, M):
   *  navigation/unmount (or a newer scan) invalidates an in-flight loop
   *  before every further fetch, decrypt, and setState — the scan used to
   *  keep fetching + decrypting every remaining patient's pattern blob
   *  after the view was gone. */
  const scanGeneration = useRef(0);
  useEffect(() => () => { scanGeneration.current += 1; }, []);
  /** This therapist's own wrap-key fingerprint (shown beside the pairing
   *  code so the patient can verify it after lookup — 2026-09-17 audit). */
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  /** SAS out-of-band comparison (2026-09-26): after generating a code, the
   *  therapist enters the PATIENT'S account id (the patient reads it from
   *  their app after entering the code) and pulls the SAS the server
   *  derived for this same (code, wrap key, patient) triple. The two
   *  humans compare by voice before the patient confirms the grant. */
  const [sasPatientId, setSasPatientId] = useState("");
  const [sasBusy, setSasBusy] = useState(false);
  const [sasError, setSasError] = useState("");
  const [sasResult, setSasResult] = useState<{ sas: string; wrap_key_fingerprint: string } | null>(null);
  /** independent audit 2026-09-27: the LOCAL server-format fingerprint of
   *  this portal's own wrap public key (null until computed / no session) —
   *  the value the SAS response's server-computed fingerprint is
   *  cross-checked against. The server derives BOTH pairing SAS strings,
   *  so the SAS itself proves nothing against a malicious server; this
   *  locally verified digest is the load-bearing substitution check. */
  const [sasLocalFingerprint, setSasLocalFingerprint] = useState<string | null>(null);
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
   *  re-derivable and the account repairable. S-4 (pentest 2026-09-26):
   *  mirrored into sessionStorage so an accidental reload of the still-open
   *  tab no longer forfeits recovery — it still dies with the browser
   *  session (and is scrubbed at every lock boundary), preserving the
   *  audit F-4 no-recovery stance for anything short of that. */
  const [interruptedSaltB64, setInterruptedSaltB64] = useState<string | null>(
    () => (props.session ? sessionStore.get(interruptedSaltKey(props.session.userId)) : null),
  );
  // --- Optional TOTP second factor (2026-09-21 audit C-2/F-4, 2026-09-22) ---
  // totpStatus: null = not yet asked, then the server's answer via /me
  // once the panel opens. totpPending holds the setup response — the
  // secret is shown exactly once, until confirmed or the panel closes.
  const [totpStatus, setTotpStatus] = useState<boolean | null>(null);
  const [totpPending, setTotpPending] = useState<{ secretBase32: string; otpauthUri: string } | null>(null);
  /** independent audit 2026-09-27: the pending setup secret is MASKED by
   *  default and revealed only through the explicit show/hide toggle — it
   *  used to sit in the DOM in plaintext for the whole setup session (the
   *  recovery codes correctly blur-clear, but the secret cannot: the user
   *  must read it while typing the confirmation code). Masked-by-default
   *  keeps shoulder/screen-recording exposure to the deliberate reveal. */
  const [totpSecretVisible, setTotpSecretVisible] = useState(false);
  const [totpPw, setTotpPw] = useState("");
  const [totpCode, setTotpCode] = useState("");
  /** S-3 (pentest 2026-09-26): the one-time recovery-code set from enable —
   *  held in state until the panel closes/sign-out, shown exactly once
   *  (the server keeps only digests; there is no re-display, ever).
   *  2026-09-26 audit round (L): the block now carries copy/download
   *  affordances through the platform seam, and the codes leave React
   *  state the moment their block loses focus (or the panel closes) —
   *  shown-once material never idles on screen. */
  const [totpBackupCodes, setTotpBackupCodes] = useState<string[] | null>(null);
  /** Honest feedback for the copy affordances ("copied" / why not). */
  const [totpCopyNote, setTotpCopyNote] = useState("");

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
        if (props.session) sessionStore.set(interruptedSaltKey(props.session.userId), newSaltB64);
        throw new Error(
          `the password change did not complete (${err instanceof Error ? err.message : "credential rotation failed"}) — `
            + "your sharing key is now wrapped under the NEW password while your sign-in password is unchanged. "
            + "Recover it with “Recover sharing key” below BEFORE leaving this page (the recovery state survives a "
            + "reload of this tab, but not closing it).",
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
      if (props.session) sessionStore.removePrefix(interruptedSaltKey(props.session.userId));
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
      // Every freshly minted secret starts masked (see totpSecretVisible).
      setTotpSecretVisible(false);
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
      const { backup_codes: backupCodes } = await api.totpEnable(verifier, totpCode);
      setTotpStatus(true);
      setTotpPending(null);
      setTotpBackupCodes(backupCodes?.length ? backupCodes : null);
      setSecNotice(
        "Two-factor authentication is on: sign-in now asks for a 6-digit code from your authenticator "
          + "(or one of the recovery codes below). Save the recovery codes now — they are shown exactly once, "
          + "and losing every code AND the authenticator still needs an operator to clear.",
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
      setTotpBackupCodes(null);
      setSecNotice("Two-factor authentication is off. Sign-in is password-only again (the recovery-code set was destroyed with it).");
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

  /** 2026-09-26 audit round (L): the copy affordances for the shown-once
   *  TOTP material go through the platform seam and report honestly. */
  const copyTotpText = async (text: string, what: string): Promise<void> => {
    const copied = await copyToClipboard(text);
    setTotpCopyNote(
      copied
        ? `${what} copied to clipboard.`
        : `could not copy the ${what} — select the text and copy it manually.`,
    );
  };

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
        // 2026-09-26 audit round (M): check the token before EVERY await
        // iteration — navigation/unmount must stop the decrypt loop, not
        // just the final setState (each iteration is a live-key decrypt
        // that keeps running on a stale screen otherwise).
        if (cancelled) return;
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
    // A new code is a NEW pairing session: its SAS differs by construction
    // (the code is an HMAC input), so any displayed comparison retires.
    setSasResult(null);
    setSasLocalFingerprint(null);
    setSasError("");
    try {
      const { code } = await api.newPairingCode();
      setPairingCode(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : "could not create a pairing code");
    } finally {
      setBusy(false);
    }
  };

  /** The therapist half of the SAS comparison: pull the server's
   *  verification code for this live pairing session + the patient's id.
   *  The code must belong to THIS therapist and still be live; anything
   *  else answers the flat 404 (unknown, expired, consumed, someone
   *  else's — indistinguishable, exactly like lookup/grant). */
  const showSas = async () => {
    if (sasBusy || !pairingCode || !sasPatientId.trim()) return;
    setSasBusy(true);
    setSasError("");
    setSasResult(null);
    setSasLocalFingerprint(null);
    try {
      const result = await api.pairingSas(sasPatientId.trim(), pairingCode);
      setSasResult({ sas: result.sas, wrap_key_fingerprint: result.wrap_key_fingerprint });
      // independent audit 2026-09-27: compute OUR OWN fingerprint of OUR OWN
      // wrap public key at the same time, in the server's short format, so
      // the render below can cross-check the two. The server computes both
      // SAS strings, so this locally verified digest — not the SAS — is the
      // substitution check that actually binds the pairing to this key.
      if (props.session) {
        try {
          setSasLocalFingerprint(await serverWrapKeyFingerprint(props.session.publicKeyB64));
        } catch {
          setSasLocalFingerprint(null);
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setSasError("pairing code not found or expired — generate a new code and try again");
      } else {
        setSasError(err instanceof Error ? err.message : "could not load the verification code");
      }
    } finally {
      setSasBusy(false);
    }
  };

  const scanCaseload = async () => {
    if (scanning || !props.session) return;
    // 2026-09-26 audit round (M): this run owns a generation token. The
    // unmount effect (and every later scan) bumps the ref, so a stale loop
    // bails before each further fetch/decrypt and before every setState —
    // navigating away mid-scan no longer keeps fetching + decrypting every
    // remaining patient's pattern blob (each of which writes a server
    // audit row) into a dead component.
    const operation = ++scanGeneration.current;
    setScanning(true);
    setError("");
    const rows: Record<string, CaseloadScanRow> = {};
    try {
      for (const patient of patients.filter((p) => p.status === "active")) {
        if (operation !== scanGeneration.current) return;
        try {
          const summary = await api.patientInsights(patient.user_id);
          // Re-check after the await: the fetch may have parked long enough
          // for the view to die (or a newer scan to start) — do not unwrap
          // and decrypt this patient's blob into a dead screen.
          if (operation !== scanGeneration.current) return;
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
              // 2026-09-26 audit follow-up (portal N-1): the same
              // freshness guard the chart applies — a replayed older blob
              // must degrade this row to the error marker, not feed stale
              // triage data into the sensitive-first sort.
              verifyInsightsGeneration(patient.user_id, payload.state_seq, summary.state_seq);
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
      if (operation === scanGeneration.current) setScan(rows);
    } finally {
      if (operation === scanGeneration.current) setScanning(false);
    }
  };

  /** 2026-09-26 audit round (M, UX copy): the scan button arms the one-time
   *  confirmation instead of starting the run — the confirmation names the
   *  access footprint in plain language before the first fetch + audit row
   *  exists. Once "don't ask again" is set, the button runs directly for
   *  the rest of this browser session (module state, never storage). */
  const startOrConfirmScan = (): void => {
    if (scanning) return;
    if (!scanConfirmedForSession && !confirmScan) {
      setConfirmScan(true);
      return;
    }
    void scanCaseload();
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
    <main className="portal-main">
      <header className="portal-head">
        <h1>Patients — {props.displayName}</h1>
        <Button label="Sign out" small onPress={props.onSignOut} />
      </header>

      <Card title="Connect a new patient">
        <Note>
          Generate a pairing code and read it to your patient. They enter it in their app, see your
          name, and confirm with their password. The code works once and expires in 15 minutes.
        </Note>
        {pairingCode && (
          <p data-testid="pairing-code" className="pairing-code">
            {pairingCode}
          </p>
        )}
        {fingerprint && (
          <p data-testid="key-fingerprint" className="fingerprint">
            {fingerprint}
          </p>
        )}
        {fingerprint && (
          <Note>Your key fingerprint — ask your patient to read theirs back after they look you up; a mismatch means a key was substituted in transit.</Note>
        )}
        {/* SAS out-of-band comparison (2026-09-26; honesty re-audit
            2026-09-27): after the patient enters the code, their app shows
            a 6-digit verification code and their account id. Enter that id
            here to pull the SAME code from this side — then compare by
            voice before they confirm the grant. THREAT-MODEL HONESTY: the
            server computes BOTH SAS strings, so against a malicious server
            the SAS alone proves nothing — it is a server-computed
            convenience for the two humans. The load-bearing substitution
            check is LOCAL: this portal independently fingerprints its OWN
            wrap public key and cross-checks the server-provided
            wrap_key_fingerprint below; a disagreement renders the visible
            mismatch warning and means do-not-proceed, full stop. */}
        {pairingCode && (
          <>
            <hr className="divider" />
            <Field
              label="Patient's account id (shown in their app)"
              value={sasPatientId}
              onChange={(value) => setSasPatientId(value.trim())}
              placeholder="32 characters"
              autoComplete="off"
            />
            <Button
              label={sasBusy ? "Checking…" : "Show verification code"}
              small
              onPress={() => void showSas()}
              disabled={sasBusy || sasPatientId.length === 0}
            />
            {sasError && <Note tone="danger" role="status">{sasError}</Note>}
            {sasResult && (() => {
              // independent audit 2026-09-27: the server value is accepted
              // only in the exact shape the contract defines (16 lowercase
              // hex chars) — anything else is treated as ABSENT, never
              // free-form rendered, and the honest note says the local
              // cross-check could not run.
              const serverFp = validServerFingerprint(sasResult.wrap_key_fingerprint);
              const mismatch = serverFp !== null && sasLocalFingerprint !== null && serverFp !== sasLocalFingerprint;
              return (
                <>
                  <p data-testid="pairing-sas" className="pairing-code">
                    {sasResult.sas}
                  </p>
                  {mismatch && (
                    <Note tone="danger" role="alert">
                      KEY FINGERPRINT MISMATCH — the fingerprint the server reported for this pairing
                      does not match the one this portal computed for your own sharing key. Do not
                      proceed: generate a new code and contact support; a key may have been substituted.
                    </Note>
                  )}
                  <Note tone={mismatch ? "danger" : "warn"}>
                    {serverFp !== null
                      ? <>Verification code for this pairing (key id {serverFp}). </>
                      : <>Verification code for this pairing. The server sent no valid key fingerprint, so it could not be verified against your own key here. </>}
                    The patient&apos;s app shows the same code after they enter yours — read it to
                    each other and confirm it matches EXACTLY before they confirm sharing. A
                    mismatch means a key was substituted: generate a new code and do not proceed.
                  </Note>
                </>
              );
            })()}
          </>
        )}
        <Button label={busy ? "Generating…" : "Generate pairing code"} onPress={newCode} disabled={busy} />
      </Card>

      <ErrorBanner message={error} />
      {loadFailed && (
        // Audit fix 17 (2026-09-21): recovery from a failed caseload load
        // used to require a reload or sign-out.
        <div className="mt-8">
          <Button label="Retry loading patients" small onPress={refresh} />
        </div>
      )}

      {sensitiveCount > 0 && (
        <div data-testid="sensitive-banner" className="mb-14">
          <Note tone="warn">
            {sensitiveCount} of your patients {sensitiveCount === 1 ? "has a sensitive card" : "have sensitive cards"} in
            their current patterns. Opening {sensitiveCount === 1 ? "that chart" : "those charts"} puts the
            non-quoting card first — the wording itself is never echoed here.
          </Note>
        </div>
      )}

      <h3 className="section-label section-label--gap">ACTIVE</h3>
      {activeAll.length > 1 && (
        <div className="toolbar">
          <Button label={scanning ? "Scanning caseload…" : "Scan caseload for triage"} small onPress={startOrConfirmScan} disabled={scanning} />
          {/* F-6 (2026-09-21): search + sort for the caseload. The classes
              carry the design (portal.css .toolbar*); the select keeps its
              native arrow suppressed and .select-wrap draws the CSP-safe
              CSS chevron in the control's right padding lane. */}
          <label className="toolbar__search">
            search{" "}
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="username…"
              aria-label="Search patients by username"
              className="input"
            />
          </label>
          <label className="toolbar__sort">
            sort{" "}
            <span className="select-wrap">
              <select
                value={sort}
                onChange={(e) => setSort(e.target.value as typeof sort)}
                aria-label="Sort patients"
                className="select"
              >
                <option value="shared">newest share</option>
                <option value="username">username</option>
                <option value="triage">triage{scan ? "" : " (scan first)"}</option>
              </select>
            </span>
          </label>
        </div>
      )}
      {/* 2026-09-26 audit round (M, UX copy): the armed one-time confirmation.
              The plain-language footprint precedes the first fetch — every
              scan is visible to the patient in the server's access log, so
              the therapist confirms the N-request/N-audit-row footprint
              before it exists. "Don't ask again" survives only this browser
              session (module state, never storage). */}
      {confirmScan && !scanning && (
        <div className="scan-confirm">
          <Note tone="warn">
            This scan downloads and decrypts every active patient&apos;s pattern data — one request and one
            audit entry per patient (their app can see that this portal read their patterns). The decrypted
            counts are held only for this screen; nothing is stored.
          </Note>
          <label className="confirm-label">
            <input
              type="checkbox"
              checked={scanNoAsk}
              onChange={(e) => setScanNoAsk(e.target.checked)}
              aria-label="Do not ask again in this browser session"
            />
            Don&apos;t ask again in this browser session
          </label>
          <div className="row">
            <Button label="Start the triage scan" small onPress={() => {
              if (scanNoAsk) scanConfirmedForSession = true;
              setConfirmScan(false);
              void scanCaseload();
            }} />
            <Button label="Cancel" small variant="ghost" onPress={() => setConfirmScan(false)} />
          </div>
        </div>
      )}
      {activeAll.length > 1 && (
        <div className="mb-10">
          <span className="hint">
            The triage scan fetches each patient&apos;s decrypted pattern counts sequentially — nothing is stored.
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
          <div className="row-between">
            <div>
              <strong className="patient-name">{patient.username}</strong>
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
          <h3 className="section-label section-label--gap">STOPPED SHARING</h3>
          {stopped.map((patient) => (
            <Card key={patient.user_id} deep>
              <div className="row-between">
                <div>
                  <strong className="patient-name patient-name--sm">{patient.username}</strong>
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
          <div className="row row--wrap">
            <Button
              label={auditBusy ? "Loading…" : "Load access history"}
              small
              onPress={loadAudit}
              disabled={auditBusy}
            />
            <span className="hint">
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
          <div className="row row--wrap">
            <Button label="Show account security" small variant="ghost" onPress={() => setSecurityOpen(true)} />
            <span className="hint">
              Change your password, recover your sharing key after an interrupted change, or rotate a
              compromised sharing key — nothing runs until you ask.
            </span>
          </div>
        ) : (
          <>
            <div className="stack">
              <h3 className="section-label section-label--flush">Change password</h3>
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
            <div className="stack">
              <hr className="divider" />
              <h3 className="section-label section-label--flush">Recover sharing key</h3>
              <Note>
                Repairs an interrupted password change: if the change failed after the sharing key was
                re-wrapped, this seals the same key back under the password you actually sign in with, so
                the account opens normally again.
              </Note>
              {interruptedSaltB64 ? (
                <Note tone="warn">
                  An interrupted change from this browser session is repairable right now — the
                  recovery state survives a reload of this tab, but not closing the browser session.
                </Note>
              ) : (
                <Note>
                  No interrupted change is remembered for this account in this browser session
                  (S-4: a change interrupted in another tab of the same session is repairable
                  there). Anything older is not recoverable — an account with no recovery path
                  stays that way (audit F-4).
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
            <div className="stack">
              <hr className="divider" />
              <h3 className="section-label section-label--flush">Rotate sharing key (suspected compromise)</h3>
              <Note>
                Publishes a brand-new sharing keypair sealed under your current password. Existing grants
                stay readable only after each patient re-wraps their data key via the pairing fingerprint
                path; grants that never re-wrap are intentionally lost — retiring the compromised key is
                the point. Your notes are unaffected: they are sealed under your password, not this key.
              </Note>
              <Field label="Current password (to authorize rotation)" value={compCurrent} onChange={setCompCurrent} type="password" autoComplete="current-password" />
              <label className="confirm-label">
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
            <div className="stack">
              <hr className="divider" />
              <h3 className="section-label section-label--flush">Two-factor authentication (authenticator app)</h3>
              {totpStatus === null && (
                <Note role="status">Checking this account&apos;s two-factor status…</Note>
              )}
              {totpStatus === false && !totpPending && (
                <>
                  <Note>
                    Optional second factor for sign-in: after it is enabled, your password AND a 6-digit
                    code from an authenticator app are both required. Enabling also mints a set of
                    single-use recovery codes (shown once) so a lost authenticator no longer needs an
                    operator to clear. Disabling two-factor needs both halves again.
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
                    never again. It is HIDDEN by default here: press “Show secret” only while you
                    are typing it in, and hide it again afterwards. Two-factor only takes effect
                    after you confirm a code below.
                  </Note>
                  {/* independent audit 2026-09-27: the secret renders MASKED
                      (same length, bullets) until the explicit toggle reveals
                      it; the otpauth URI embeds the same secret, so it only
                      exists in the DOM while revealed. Panel close/confirm
                      still clears the material from state entirely. */}
                  <div className="totp-secret">
                    <p
                      aria-label="Authenticator secret (manual entry)"
                      className="mono mono-secret"
                    >
                      {totpSecretVisible
                        ? totpPending.secretBase32
                        : totpPending.secretBase32.replace(/\S/g, "•")}
                    </p>
                    {totpSecretVisible && (
                      <p
                        aria-label="otpauth URI for apps that accept it"
                        className="mono mono-uri"
                      >
                        {totpPending.otpauthUri}
                      </p>
                    )}
                    <div className="row row--wrap">
                      <Button
                        label={totpSecretVisible ? "Hide secret" : "Show secret"}
                        small
                        variant="ghost"
                        onPress={() => setTotpSecretVisible((visible) => !visible)}
                      />
                      <Button
                        label="Copy secret"
                        small
                        onPress={() => void copyTotpText(`${totpPending.secretBase32}`, "secret")}
                      />
                      {totpCopyNote && <span className="hint" role="status">{totpCopyNote}</span>}
                    </div>
                  </div>
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
                    Enabled — sign-in requires your password and a current 6-digit code (or an unused
                    recovery code).
                  </Note>
                  {totpBackupCodes && (
                    /* 2026-09-26 audit round (L): the shown-once codes are
                        focusable so they can be BLUR-CLEARED — the moment
                        focus leaves this block (copied or not), the codes
                        leave React state; panel close clears them too. The
                        "shown EXACTLY ONCE" copy stays accurate because the
                        server keeps only digests: there is no re-display. */
                    <div
                      className="totp-codes"
                      tabIndex={0}
                      aria-label="One-time recovery codes (cleared when this block loses focus)"
                      onBlur={(event) => {
                        const next = event.relatedTarget as Node | null;
                        if (next && event.currentTarget.contains(next)) return;
                        setTotpBackupCodes(null);
                        setTotpCopyNote("");
                      }}
                    >
                      <Note tone="warn">
                        Recovery codes — shown EXACTLY ONCE, never again. Each works one time in place
                        of a 6-digit code at sign-in. Copy or download them NOW: losing every code
                        AND the authenticator leaves an operator clear as the only path.
                      </Note>
                      <div aria-label="One-time recovery codes" className="mono recovery-codes">
                        {totpBackupCodes.map((code) => (
                          <p key={code}>{code}</p>
                        ))}
                      </div>
                      <div className="row row--wrap">
                        <Button
                          label="Copy recovery codes"
                          small
                          onPress={() => void copyTotpText(totpBackupCodes.join("\n"), "recovery codes")}
                        />
                        <Button
                          label="Download recovery codes (.txt)"
                          small
                          variant="ghost"
                          onPress={() =>
                            downloadTextFile(
                              "mindpattern-recovery-codes.txt",
                              "MindPattern therapist portal — one-time recovery codes\n\n"
                                + `${totpBackupCodes.join("\n")}\n\n`
                                + "Each code works one time in place of a 6-digit sign-in code.\n"
                                + "They are shown only once; keep this file somewhere safe.",
                            )
                          }
                        />
                        {totpCopyNote && <span className="hint" role="status">{totpCopyNote}</span>}
                      </div>
                    </div>
                  )}
                  {!totpBackupCodes && (
                    <Note tone="danger">
                      Turning two-factor off needs your password AND a current code. If the authenticator
                      is lost, sign in with a recovery code — losing every code AND the authenticator
                      needs an operator to clear.
                    </Note>
                  )}
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
              variant="ghost"
              onPress={() => {
                setSecurityOpen(false);
                // The pending secret AND the one-time recovery codes are
                // shown-once material: closing the panel discards them (a
                // fresh setup mints a fresh secret; the codes have no
                // re-display, ever).
                setTotpPending(null);
                setTotpBackupCodes(null);
                setTotpCopyNote("");
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
