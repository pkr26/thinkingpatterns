/**
 * Login / therapist registration. The password NEVER leaves this form:
 * it is stretched into the auth key (sent) and the portal wrap KEK (kept
 * in memory) exactly like the patient apps.
 */
import { useEffect, useRef, useState } from "react";
import { api, auth, ApiError, clearSession, MINIMUM_AGE_ATTESTATION, normalizeApiBaseUrl, setSession, type TokenResponse } from "../api";
import { deriveMasterKey, derivePortalKeys, fromBase64, generateTherapistKeyPair, toBase64 } from "../crypto";
import { Button, Card, Disclosure, ErrorBanner, Field, Note, PasswordStrengthMeter } from "../ui";
import { currentOrigin, randomBytes } from "../platform";

export interface PortalKeys {
  username: string;
  userId: string;
  wrapKek: Uint8Array<ArrayBuffer>;
  noteKey: Uint8Array<ArrayBuffer>;
}

interface PendingMfaEnrollment {
  keys: PortalKeys;
  token: TokenResponse;
  baseUrl: string;
  verifier: string;
  secret: string;
  uri: string;
  backupCodes: string[] | null;
  handoffFailed?: boolean;
}

/**
 * Registration is client-side zero knowledge: the API only receives a
 * verifier, so it cannot inspect a password later.  Enforce a practical
 * password-manager-friendly policy before deriving a permanent account key.
 * A long passphrase is accepted without arbitrary symbol rules; shorter
 * passwords need several character classes.
 */
export function passwordPolicyError(password: string): string {
  if (password.length < 12) return "Use at least 12 characters.";
  const classes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)]
    .filter(Boolean).length;
  if (password.length < 16 && classes < 3) {
    return "Use a 16-character passphrase, or 12+ characters from at least three character types.";
  }
  if (/^(.)\1+$/u.test(password) || /^(?:password|123456|qwerty|letmein|welcome|mindpattern|fathom|journal|admin|changeme)/i.test(password) || /password/i.test(password)) {
    return "Choose a less common password; avoid repeated characters and common password words.";
  }
  return "";
}

/** Visual strength (0–4) for the registration meter (2026-09-26 UX
 *  parity): the same ladder the patient web app's meter climbs — empty
 *  shows nothing, under the 12-character floor is Weak, a policy-failing
 *  12+ password is Fair, a policy-passing 12–15 character password is
 *  Good, and 16+ is Strong. Display-only; the enforceable contract stays
 *  passwordPolicyError above (and mirrors the policy text the form
 *  already shows). */
export function passwordStrength(password: string): 0 | 1 | 2 | 3 | 4 {
  if (password.length === 0) return 0;
  if (password.length < 12) return 1;
  if (passwordPolicyError(password) !== "") return 2;
  if (password.length < 16) return 3;
  return 4;
}

export function normalizeBaseUrl(candidate: string): string {
  return normalizeApiBaseUrl(candidate);
}

function wipeKeys(
  keys: (Pick<PortalKeys, "wrapKek" | "noteKey"> & { authKey?: Uint8Array<ArrayBuffer> }) | undefined,
): void {
  keys?.wrapKek.fill(0);
  keys?.noteKey.fill(0);
  // Audit fix P-1 (2026-09-20): the verifier bytes are wiped eagerly at the
  // network send; this covers the failure paths that throw before it.
  keys?.authKey?.fill(0);
}

/** S-3 (pentest 2026-09-26): the second-factor field accepts BOTH forms —
 * the 6-digit authenticator code or a 10-char single-use recovery code
 * (case-insensitive; the server normalizes). */
const TOTP_OR_RECOVERY = /^(\d{6}|[A-Z0-9]{10})$/i;

/** Server detail is untrusted and may be non-English. API failures map to
 * stable client-owned copy; only local errors retain their authored text. */
function friendlyLoginError(err: unknown): string {
  const message = err instanceof Error ? err.message : "";
  if ((err instanceof ApiError && err.code === "invalid_credentials") || message === "invalid credentials") {
    return "Sign-in failed — check your username and password.";
  }
  if (err instanceof ApiError) {
    if (err.status === 0) return "Could not reach the server — check your connection.";
    if (err.status === 429) return "Too many sign-in attempts — wait a moment and try again.";
    if (err.status >= 500) return "The server could not complete sign-in — try again in a moment.";
    return "Sign-in failed — check your details and try again.";
  }
  return err instanceof Error ? err.message : "sign-in failed";
}

function friendlyRegistrationError(err: unknown): string {
  if (!(err instanceof ApiError)) return err instanceof Error ? err.message : "registration failed";
  if (err.status === 0) return "Could not reach the server — check your connection.";
  if (err.status === 403) return "This server did not authorize clinician enrollment. Contact your organization administrator.";
  if (err.status === 409) return "That username is already in use. Choose another username.";
  if (err.status === 429) return "Too many registration attempts — wait a moment and try again.";
  if (err.status >= 500) return "The server could not create the account — try again in a moment.";
  return "Registration failed — check the form and try again.";
}

export function LoginView(props: { onReady: (keys: PortalKeys, token: TokenResponse, baseUrl: string) => void | Promise<void> }): React.JSX.Element {
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [enrollmentToken, setEnrollmentToken] = useState("");
  const [ageConfirmed, setAgeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);
  const [sharingPolicyError, setSharingPolicyError] = useState("");
  // Therapist MFA is mandatory before patient-data access. Existing
  // enrolled accounts may still answer totp_required after the password
  // half validates; a newly registered or legacy-unenrolled account is
  // held in the blocking enrollment state below before onReady can mount
  // any caseload surface.
  const [totpNeeded, setTotpNeeded] = useState(false);
  const [totpCode, setTotpCode] = useState("");
  const [mfaEnrollment, setMfaEnrollment] = useState<PendingMfaEnrollment | null>(null);
  const [mfaCode, setMfaCode] = useState("");

  // The official portal is deliberately same-origin only. A user-editable
  // HTTPS endpoint can be an attacker server: it could choose a salt and
  // collect the derived verifier (or an organization enrollment token) for
  // offline guessing. Deployment routes `/api` through the same TLS origin;
  // development uses Vite's same-origin proxy.
  const server = currentOrigin();
  const baseUrl = normalizeBaseUrl(server);
  const passwordError = passwordPolicyError(password);
  const serverError = !baseUrl
    ? "This portal must be served from its configured HTTPS origin (or a loopback development origin)."
    : "";
  // Audit fix 18 (2026-09-21): the fields live in a real <form>, so Enter
  // submits. These guards mirror the submit buttons' disabled logic — an
  // incomplete form stays inert instead of firing a doomed request.
  const canSignIn = Boolean(username && password && baseUrl && (!totpNeeded || TOTP_OR_RECOVERY.test(totpCode)));
  const canRegister = Boolean(username && password && password2 && !passwordError && ageConfirmed && baseUrl && sharingAvailable === true);

  // Never guess that a random server can create a clinician account.  The
  // backend advertises this non-personal deployment policy specifically so
  // the portal can distinguish an administrative block from a login error.
  useEffect(() => {
    let cancelled = false;
    if (mode !== "register" || !baseUrl) {
      setSharingAvailable(null);
      setSharingPolicyError("");
      return () => { cancelled = true; };
    }
    setSharingAvailable(null);
    setSharingPolicyError("");
    void auth.meta(baseUrl)
      .then((meta) => {
        if (!cancelled) setSharingAvailable(meta.sharing_available === true);
      })
      .catch(() => {
        if (!cancelled) setSharingPolicyError("Could not confirm this server's clinician enrollment policy. Contact its administrator.");
      });
    return () => { cancelled = true; };
  }, [mode, baseUrl]);

  const signIn = async (code?: string) => {
    setBusy(true);
    setError("");
    let portalKeys: PortalKeys | undefined;
    let derivedKeys: Awaited<ReturnType<typeof derivePortalKeys>> | undefined;
    let transferred = false;
    let keepPassword = false;
    try {
      const { salt } = await auth.saltFor(baseUrl, username);
      const saltBytes = fromBase64(salt);
      let master: Awaited<ReturnType<typeof deriveMasterKey>>;
      try {
        master = await deriveMasterKey(password, saltBytes);
      } finally {
        saltBytes.fill(0);
      }
      try {
        derivedKeys = await derivePortalKeys(master);
      } finally {
        master.fill(0);
      }
      // Audit fix P-1 (2026-09-20): the verifier's base64 string exists only
      // for this request — derived here at the send from the raw bytes, which
      // are wiped the moment the request is built (the success path below
      // transfers the other keys without the final wipe).
      const verifier = toBase64(derivedKeys.authKey);
      const token = await auth.login(
        baseUrl,
        username,
        verifier,
        code === undefined ? undefined : code,
      );
      // A retired form no longer owns the shared bearer slot or a handoff.
      // Revoke its own late token without touching a replacement session.
      if (!mounted.current) {
        void auth.logoutBearer(baseUrl, token.token).catch(() => undefined);
        return;
      }
      if (token.role !== "therapist") {
        // S-12 (pentest 2026-09-26): the server has already minted a 24 h
        // bearer. Dropping it locally left it live server-side; revoke it
        // best-effort (epoch bump — same contract as every other portal
        // lock boundary) before surfacing the role error.
        void auth.logoutBearer(baseUrl, token.token).catch(() => undefined);
        throw new Error("this is a patient account — the portal is for therapist accounts");
      }
      setSession(token.token, baseUrl);
      portalKeys = {
        username, userId: token.user_id, wrapKek: derivedKeys.wrapKek, noteKey: derivedKeys.noteKey,
      };
      if (token.mfa_enrollment_required === true) {
        const setup = await api.totpSetup(verifier);
        if (!mounted.current) {
          void auth.logoutBearer(baseUrl, token.token).catch(() => undefined);
          return;
        }
        derivedKeys.authKey.fill(0);
        setMfaEnrollment({
          keys: portalKeys,
          token,
          baseUrl,
          verifier,
          secret: setup.secret_base32,
          uri: setup.otpauth_uri,
          backupCodes: null,
        });
        transferred = true;
        return;
      }
      derivedKeys.authKey.fill(0);
      await props.onReady(portalKeys, token, baseUrl);
      transferred = true;
    } catch (err) {
      if (err instanceof ApiError && err.code === "totp_required") {
        // The password half validated; the account wants its second factor.
        setTotpNeeded(true);
        keepPassword = true;
        setError("Enter the 6-digit code from your authenticator app — or one of your recovery codes.");
      } else if (err instanceof ApiError && err.code === "totp_code_invalid" && totpNeeded) {
        // Still inside the TOTP stage: the password was right, only the
        // code was wrong/stale/consumed — let the user try the next code
        // without retyping the password.
        keepPassword = true;
        setError("That code was wrong or already used — enter the current one (or a recovery code).");
      } else {
        setError(friendlyLoginError(err));
      }
    } finally {
      // Password strings cannot be overwritten in JavaScript, but removing
      // them from component state promptly keeps them out of a live form.
      // Exception: while the TOTP stage is armed the retry needs the
      // password to re-derive the verifier — it is cleared the moment the
      // stage ends (success, non-TOTP error, or leaving the form).
      if (!keepPassword) setPassword("");
      if (!transferred) {
        wipeKeys(portalKeys);
        wipeKeys(derivedKeys);
        if (mounted.current) clearSession();
      }
      setBusy(false);
    }
  };

  const register = async () => {
    if (!ageConfirmed) {
      setError("Confirm that you are 18 or older before creating an account.");
      return;
    }
    if (sharingAvailable !== true) {
      setError(
        sharingAvailable === false
          ? "New clinician enrollment is not available on this server. Contact your organization administrator."
          : "Checking this server's clinician enrollment policy. Please try again in a moment.",
      );
      return;
    }
    if (password !== password2) {
      setError("the two passwords do not match");
      return;
    }
    if (passwordError) {
      setError(passwordError);
      return;
    }
    setBusy(true);
    setError("");
    let portalKeys: PortalKeys | undefined;
    let derivedKeys: Awaited<ReturnType<typeof derivePortalKeys>> | undefined;
    let transferred = false;
    try {
      // F-6 (2026-09-21): through the platform seam, not bare crypto.
      const saltBytes = randomBytes(16);
      const salt = btoa(String.fromCharCode(...saltBytes));
      const master = await deriveMasterKey(password, saltBytes);
      try {
        derivedKeys = await derivePortalKeys(master);
      } finally {
        master.fill(0);
        saltBytes.fill(0);
      }
      // Audit fix P-1 (2026-09-20): key generation and upload-sealing are one
      // call — the raw private key never exists as a base64 string, and this
      // flow only ever holds the sealed blob.
      const pair = await generateTherapistKeyPair(derivedKeys.wrapKek, username);
      const verifier = toBase64(derivedKeys.authKey);
      const registration = {
        username,
        salt,
        // P-1 (2026-09-20): the verifier string is derived here, at the
        // network send, never stored on a long-lived object field.
        verifier,
        display_name: displayName || username,
        wrap_pub_key: pair.publicKeySpkiB64,
        wrap_key_blob: pair.wrapKeyBlobB64,
        age_attestation: MINIMUM_AGE_ATTESTATION,
      };
      const token = enrollmentToken.trim()
        ? await auth.registerTherapist(baseUrl, registration, enrollmentToken)
        : await auth.registerTherapist(baseUrl, registration);
      if (!mounted.current) {
        void auth.logoutBearer(baseUrl, token.token).catch(() => undefined);
        return;
      }
      setSession(token.token, baseUrl);
      portalKeys = {
        username, userId: token.user_id, wrapKek: derivedKeys.wrapKek, noteKey: derivedKeys.noteKey,
      };
      if (token.mfa_enrollment_required === true) {
        const setup = await api.totpSetup(verifier);
        if (!mounted.current) {
          void auth.logoutBearer(baseUrl, token.token).catch(() => undefined);
          return;
        }
        derivedKeys.authKey.fill(0);
        setMfaEnrollment({
          keys: portalKeys,
          token,
          baseUrl,
          verifier,
          secret: setup.secret_base32,
          uri: setup.otpauth_uri,
          backupCodes: null,
        });
        transferred = true;
        return;
      }
      derivedKeys.authKey.fill(0);
      await props.onReady(portalKeys, token, baseUrl);
      transferred = true;
    } catch (err) {
      setError(friendlyRegistrationError(err));
    } finally {
      setPassword("");
      setPassword2("");
      setEnrollmentToken("");
      setAgeConfirmed(false);
      if (!transferred) {
        wipeKeys(portalKeys);
        wipeKeys(derivedKeys);
        if (mounted.current) clearSession();
      }
      setBusy(false);
    }
  };

  const enableRequiredMfa = async (): Promise<void> => {
    if (!mfaEnrollment || !/^\d{6}$/.test(mfaCode) || busy) return;
    setBusy(true);
    setError("");
    try {
      const result = await api.totpEnable(mfaEnrollment.verifier, mfaCode);
      // The verifier and setup secret/URI have completed their only job.
      // Drop them before the backup-code acknowledgement screen remains up.
      setMfaEnrollment({ ...mfaEnrollment, verifier: "", secret: "", uri: "", backupCodes: result.backup_codes });
      setMfaCode("");
    } catch {
      setError("That authenticator code was not accepted. Enter the current 6-digit code and try again.");
    } finally {
      setBusy(false);
    }
  };

  const finishRequiredMfa = async (): Promise<void> => {
    if (!mfaEnrollment?.backupCodes || busy) return;
    setBusy(true);
    setError("");
    try {
      await props.onReady(
        mfaEnrollment.keys,
        { ...mfaEnrollment.token, mfa_enrollment_required: false },
        mfaEnrollment.baseUrl,
      );
      setMfaEnrollment(null);
    } catch {
      void auth.logoutBearer(mfaEnrollment.baseUrl, mfaEnrollment.token.token).catch(() => undefined);
      wipeKeys(mfaEnrollment.keys);
      clearSession();
      // Keep only the one-time backup codes visible until the clinician
      // acknowledges them; every credential/setup secret and live key is
      // retired immediately after the failed handoff.
      setMfaEnrollment({
        ...mfaEnrollment,
        token: { ...mfaEnrollment.token, token: "" },
        verifier: "",
        secret: "",
        uri: "",
        handoffFailed: true,
      });
      setError("Two-factor authentication is enabled, but the portal could not finish opening. Try signing in again.");
    } finally {
      setBusy(false);
    }
  };

  const cancelRequiredMfa = (): void => {
    if (!mfaEnrollment || busy) return;
    if (mfaEnrollment.token.token) {
      void auth.logoutBearer(mfaEnrollment.baseUrl, mfaEnrollment.token.token).catch(() => undefined);
    }
    wipeKeys(mfaEnrollment.keys);
    clearSession();
    setMfaEnrollment(null);
    setMfaCode("");
    setError("");
  };

  // Audit fix 18 (2026-09-21): real form semantics — Enter in any field
  // submits; preventDefault keeps the browser from reloading the SPA.
  const submit = (event: React.FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (busy) return;
    if (mode === "login") {
      if (canSignIn) void signIn(totpNeeded ? totpCode : undefined);
    } else if (canRegister) {
      void register();
    }
  };

  if (mfaEnrollment) {
    return (
      <main className="login-main">
        <div className="login-wrap">
          <h1 className="login-title">Fathom · Therapist portal</h1>
          <Card title="Set up two-factor authentication to continue">
            <Note tone="danger">Patient data stays locked until two-factor authentication is enabled.</Note>
            {mfaEnrollment.backupCodes === null ? (
              <>
                <Note>Add this account to your authenticator app, then enter its current 6-digit code.</Note>
                <div className="totp-secret"><code>{mfaEnrollment.secret}</code></div>
                <Disclosure summary="Can’t scan a QR code? Show the setup URI">
                  <code>{mfaEnrollment.uri}</code>
                </Disclosure>
                <Field
                  label="Authenticator code"
                  value={mfaCode}
                  onChange={(value) => setMfaCode(value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="123456"
                  autoComplete="one-time-code"
                />
                <Button label={busy ? "Enabling…" : "Enable two-factor authentication"} onPress={() => void enableRequiredMfa()} disabled={busy || !/^\d{6}$/.test(mfaCode)} />
              </>
            ) : (
              <>
                <Note tone="danger">Save these one-time recovery codes now. They will not be shown again.</Note>
                <div className="totp-codes">
                  {mfaEnrollment.backupCodes.map((code) => <code key={code}>{code}</code>)}
                </div>
                {mfaEnrollment.handoffFailed ? (
                  <Button label="I saved the codes — return to sign in" onPress={cancelRequiredMfa} disabled={busy} />
                ) : (
                  <Button label={busy ? "Opening portal…" : "I saved the codes — continue"} onPress={() => void finishRequiredMfa()} disabled={busy} />
                )}
              </>
            )}
            <ErrorBanner message={error} />
            <Button label="Cancel and sign out" onPress={cancelRequiredMfa} disabled={busy} small />
          </Card>
        </div>
      </main>
    );
  }

  return (
    // 2026-09-26 CSP hardening: the login chrome renders through the
    // .login-* token classes in portal.css — no inline style attributes
    // remain anywhere in the portal, so style-src drops 'unsafe-inline'.
    <main className="login-main">
      <div className="login-wrap">
        <h1 className="login-title">Fathom · Therapist portal</h1>
        <Card title={mode === "login" ? "Sign in" : "Create a therapist account"}>
          <form onSubmit={submit} className="login-form">
            {mode === "register" && (
              <>
                <Field label="Your name (shown to patients)" value={displayName} onChange={setDisplayName} placeholder="Dr. Jane Omega" autoComplete="name" />
                <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" autoComplete="username" />
              </>
            )}
            {mode === "login" && <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" autoComplete="username" />}
            <Field label="Password" value={password} onChange={setPassword} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} reveal />
            {mode === "register" && <PasswordStrengthMeter strength={passwordStrength(password)} />}
            {mode === "login" && totpNeeded && (
              <Field
                label="Authenticator code (or recovery code)"
                value={totpCode}
                onChange={(value) => setTotpCode(value.trim().slice(0, 10))}
                placeholder="123456"
                autoComplete="one-time-code"
              />
            )}
            {mode === "register" && (
              <Field label="Repeat password" value={password2} onChange={setPassword2} type="password" autoComplete="new-password" reveal />
            )}
            {mode === "register" && (
              <>
                <Field
                  label="Clinician enrollment token (if issued)"
                  value={enrollmentToken}
                  onChange={setEnrollmentToken}
                  type="password"
                  autoComplete="one-time-code"
                  placeholder="Organization-issued token"
                />
                {sharingAvailable === false && (
                  <Note tone="danger" role="status">New clinician enrollment is unavailable on this server. Contact your organization administrator.</Note>
                )}
                {sharingAvailable === null && !sharingPolicyError && baseUrl && (
                  <Note role="status">Checking this server&apos;s clinician enrollment policy…</Note>
                )}
                {sharingPolicyError && <Note tone="danger" role="status">{sharingPolicyError}</Note>}
                <label className="row">
                  <input
                    type="checkbox"
                    checked={ageConfirmed}
                    onChange={(event) => setAgeConfirmed(event.target.checked)}
                  />
                  <span>I confirm that I am 18 or older.</span>
                </label>
              </>
            )}
            <Note>
              Server: this portal&apos;s own secure origin. It cannot be changed from the sign-in screen.
            </Note>
            {serverError && <Note tone="danger" role="status">{serverError}</Note>}
            {mode === "register" && (
              <>
                <Note>
                  Choose a password of at least 12 characters. Use a 16-character passphrase, or use at least three character types at 12–15 characters.
                </Note>
                <Note>
                  If your organization issued a clinician enrollment token, enter it here. It is sent only to this portal&apos;s same-origin secure API connection and is never stored by this portal.
                </Note>
                {/* Audit F-4 (2026-09-21): the credential lifecycle has no
                    reset path in v1 — say so BEFORE the account exists. */}
                <Note tone="danger">
                  There is no password reset and no account recovery. Your sharing key is
                  wrapped to this password alone: if you forget it, your account and every
                  shared note become permanently unreadable. Save the password in a
                  password manager before you continue.
                </Note>
              </>
            )}
            <ErrorBanner message={error} />
            {mode === "login" ? (
              <>
                {/* 2026-09-28 audit F1: the primary action is type=submit,
                    so a real browser's Enter-in-any-field submits the form
                    (implicit submission). The old always-type=button button
                    left the multi-field form with NO submit control — Enter
                    silently did nothing. No onPress: the click routes through
                    the same form onSubmit. */}
                <Button
                  label={busy ? "Signing in…" : totpNeeded ? "Verify code" : "Sign in"}
                  type="submit"
                  disabled={busy || !canSignIn}
                />
                <Button label="Create a therapist account instead" small onPress={() => { setMode("register"); setError(""); setAgeConfirmed(false); setTotpNeeded(false); setTotpCode(""); }} disabled={busy} />
              </>
            ) : (
              <>
                <Button label={busy ? "Creating…" : "Create account"} type="submit" disabled={busy || !canRegister} />
                <Button label="Back to sign in" small onPress={() => { setMode("login"); setError(""); setAgeConfirmed(false); setTotpNeeded(false); setTotpCode(""); }} disabled={busy} />
              </>
            )}
            {/* 2026-09-28 audit F5: the full crypto-honesty paragraph is one
                click away instead of a standing wall of text. */}
            <Disclosure summary="How your password is protected">
              Your password never leaves this page: the server stores only a hash of a derived key, and
              your sharing key is decryptable only with your password.
            </Disclosure>
          </form>
        </Card>
      </div>
    </main>
  );
}
