/**
 * Login / therapist registration. The password NEVER leaves this form:
 * it is stretched into the auth key (sent) and the portal wrap KEK (kept
 * in memory) exactly like the patient apps.
 */
import { useEffect, useState } from "react";
import { auth, ApiError, clearSession, normalizeApiBaseUrl, setSession, type TokenResponse } from "../api";
import { deriveMasterKey, derivePortalKeys, fromBase64, generateTherapistKeyPair, toBase64 } from "../crypto";
import { Button, Card, ErrorBanner, Field, Note, theme } from "../ui";
import { currentOrigin, randomBytes } from "../platform";

export interface PortalKeys {
  username: string;
  userId: string;
  wrapKek: Uint8Array<ArrayBuffer>;
  noteKey: Uint8Array<ArrayBuffer>;
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
  return "";
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

export function LoginView(props: { onReady: (keys: PortalKeys, token: TokenResponse, baseUrl: string) => void | Promise<void> }): React.JSX.Element {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [enrollmentToken, setEnrollmentToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);
  const [sharingPolicyError, setSharingPolicyError] = useState("");
  // Optional therapist TOTP (2026-09-22): the server answers 401
  // totp_required AFTER the password half validated; this form then shows
  // the code field and re-sends the full login with it. The password stays
  // in state across that boundary only — the retry needs it to re-derive
  // the verifier (it is wiped on every non-TOTP outcome).
  const [totpNeeded, setTotpNeeded] = useState(false);
  const [totpCode, setTotpCode] = useState("");

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
  const canSignIn = Boolean(username && password && baseUrl && (!totpNeeded || /^\d{6}$/.test(totpCode)));
  const canRegister = Boolean(username && password && password2 && !passwordError && baseUrl && sharingAvailable === true);

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
      const token = await auth.login(
        baseUrl,
        username,
        toBase64(derivedKeys.authKey),
        code === undefined ? undefined : code,
      );
      derivedKeys.authKey.fill(0);
      if (token.role !== "therapist") {
        throw new ApiError(403, "this is a patient account — the portal is for therapist accounts");
      }
      setSession(token.token, baseUrl);
      portalKeys = {
        username, userId: token.user_id, wrapKek: derivedKeys.wrapKek, noteKey: derivedKeys.noteKey,
      };
      await props.onReady(portalKeys, token, baseUrl);
      transferred = true;
    } catch (err) {
      if (err instanceof ApiError && err.code === "totp_required") {
        // The password half validated; the account wants its second factor.
        setTotpNeeded(true);
        keepPassword = true;
        setError("Enter the 6-digit code from your authenticator app.");
      } else if (err instanceof ApiError && err.code === "totp_code_invalid" && totpNeeded) {
        // Still inside the TOTP stage: the password was right, only the
        // code was wrong/stale/consumed — let the user try the next code
        // without retyping the password.
        keepPassword = true;
        setError("That code was wrong or already used — enter the current one.");
      } else {
        setError(err instanceof Error ? err.message : "sign-in failed");
      }
    } finally {
      // Password strings cannot be overwritten in JavaScript, but removing
      // them from component state promptly keeps them out of a live form.
      // Exception: while the TOTP stage is armed the retry needs the
      // password to re-derive the verifier — it is cleared the moment the
      // stage ends (success, non-TOTP error, or leaving the form).
      if (!keepPassword) setPassword("");
      if (!transferred) {
        wipeKeys(portalKeys ?? derivedKeys);
        clearSession();
      }
      setBusy(false);
    }
  };

  const register = async () => {
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
      const registration = {
        username,
        salt,
        // P-1 (2026-09-20): the verifier string is derived here, at the
        // network send, never stored on a long-lived object field.
        verifier: toBase64(derivedKeys.authKey),
        display_name: displayName || username,
        wrap_pub_key: pair.publicKeySpkiB64,
        wrap_key_blob: pair.wrapKeyBlobB64,
      };
      derivedKeys.authKey.fill(0);
      const token = enrollmentToken.trim()
        ? await auth.registerTherapist(baseUrl, registration, enrollmentToken)
        : await auth.registerTherapist(baseUrl, registration);
      setSession(token.token, baseUrl);
      portalKeys = {
        username, userId: token.user_id, wrapKek: derivedKeys.wrapKek, noteKey: derivedKeys.noteKey,
      };
      await props.onReady(portalKeys, token, baseUrl);
      transferred = true;
    } catch (err) {
      setError(err instanceof Error ? err.message : "registration failed");
    } finally {
      setPassword("");
      setPassword2("");
      setEnrollmentToken("");
      if (!transferred) {
        wipeKeys(portalKeys ?? derivedKeys);
        clearSession();
      }
      setBusy(false);
    }
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

  return (
    <main style={{ backgroundColor: theme.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ width: 420, display: "flex", flexDirection: "column", gap: 14 }}>
        <h1 style={{ color: theme.text, fontSize: 22, margin: 0 }}>MindPattern · Therapist portal</h1>
        <Card title={mode === "login" ? "Sign in" : "Create a therapist account"}>
          <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {mode === "register" && (
              <>
                <Field label="Your name (shown to patients)" value={displayName} onChange={setDisplayName} placeholder="Dr. Jane Omega" autoComplete="name" />
                <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" autoComplete="username" />
              </>
            )}
            {mode === "login" && <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" autoComplete="username" />}
            <Field label="Password" value={password} onChange={setPassword} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} />
            {mode === "login" && totpNeeded && (
              <Field
                label="Authenticator code"
                value={totpCode}
                onChange={(value) => setTotpCode(value.replace(/\D/g, "").slice(0, 6))}
                placeholder="123456"
                autoComplete="one-time-code"
              />
            )}
            {mode === "register" && (
              <Field label="Repeat password" value={password2} onChange={setPassword2} type="password" autoComplete="new-password" />
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
                <Button
                  label={busy ? "Signing in…" : totpNeeded ? "Verify code" : "Sign in"}
                  onPress={() => void signIn(totpNeeded ? totpCode : undefined)}
                  disabled={busy || !canSignIn}
                />
                <Button label="Create a therapist account instead" small onPress={() => { setMode("register"); setError(""); setTotpNeeded(false); setTotpCode(""); }} disabled={busy} />
              </>
            ) : (
              <>
                <Button label={busy ? "Creating…" : "Create account"} onPress={register} disabled={busy || !canRegister} />
                <Button label="Back to sign in" small onPress={() => { setMode("login"); setError(""); setTotpNeeded(false); setTotpCode(""); }} disabled={busy} />
              </>
            )}
            <Note>
              Your password never leaves this page: the server stores only a hash of a derived key, and
              your sharing key is decryptable only with your password.
            </Note>
          </form>
        </Card>
      </div>
    </main>
  );
}
