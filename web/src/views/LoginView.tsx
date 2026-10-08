/**
 * Patient sign-in and registration with client-side key derivation.
 *
 * Passwords remain local; only derived verifiers cross the network. New
 * accounts wrap a random data key in a v2 envelope. Existing v1 accounts keep
 * their original derivation. Transient key material is erased on failure.
 * Registration records an affirmative age attestation without a birth date.
 */
import { useState } from "react";
import { ApiError, api, auth, clearSession, MINIMUM_AGE_ATTESTATION, setSession, type TokenResponse } from "../api/client";
import { displayError } from "../errors";
import { deriveMasterKey, fromBase64, toBase64, zeroize, KDF_ITERATIONS, type Bytes } from "../crypto/core";
import { createRegistrationEnvelope, unwrapEnvelope, validateKdfParams } from "../crypto/envelope";
import { derivePatientKeys, type PatientKeys } from "../crypto/keys";
import { randomBytes } from "../platform";
import { t } from "../strings";
import { vault } from "../vault";
import { Button, Card, Checkbox, ErrorBanner, Field, Logo, Note } from "../ui";

/** Mirrors the backend's USERNAME_PATTERN (schemas.py): honest client-side
 *  validation so the server's validation_error never surprises anyone. */
const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,64}$/;
/** Server account ids are 32-hex (uuid4().hex). The login response is
 *  hostile-server-controllable text like any other server payload: a
 *  malformed id must never reach the vault owner binding or storage keys
 *  (mobile L-7 parity, fix W-5, audit 2026-09-25). */
const USER_ID_PATTERN = /^[0-9a-f]{32}$/;
const PASSWORD_MIN = 12;

export interface LoginSuccess {
  userId: string;
  username: string;
}

/** On-device password policy (identical to mobile, incl. its L-6 shape
 *  rules): 12+ characters, below 16 at least three of the four character
 *  classes, and never the trivially-guessable families — a zero-knowledge
 *  design leaves the server only the derived verifier, so the POLICY is
 *  entirely client-side (fix W-3, audit 2026-09-25). These are the
 *  families the mobile on-device unlock oracle would otherwise crack in
 *  minutes on a stolen phone. */
const COMMON_PASSWORD_WORDS = [
  "fathom",
  "password", "qwerty", "123456", "12345678", "123456789", "letmein",
  "iloveyou", "welcome", "admin", "monkey", "dragon", "sunshine",
  "princess", "football", "baseball", "master", "abc123", "111111",
  "mindpattern", "journal",
];

/** M-W5 (audit 2026-09-26): policy copy resolves through the t() catalog
 *  so a Spanish device reads its own password rules. */
export function passwordPolicyError(password: string): string | null {
  if (password.length < PASSWORD_MIN) return t("login.policyMinWeb", { min: PASSWORD_MIN });
  if (password.length < 16) {
    const variety =
      (/[a-z]/.test(password) ? 1 : 0)
      + (/[A-Z]/.test(password) ? 1 : 0)
      + (/[0-9]/.test(password) ? 1 : 0)
      + (/[^a-zA-Z0-9]/.test(password) ? 1 : 0);
    if (variety < 3) return t("login.policyVarietyWeb");
  }
  const lowered = password.toLowerCase();
  if (
    COMMON_PASSWORD_WORDS.some((word) => lowered.includes(word))
    || /^(.)\1+$/.test(password)
    || /^(0123|1234|2345|3456|4567|5678|6789|qwer|asdf|zxcv)/i.test(password)
  ) {
    return t("login.policyCommonWeb");
  }
  return null;
}

/** Visual strength (1–4) for the registration meter — display-only; the
 *  enforceable contract stays passwordPolicyError above. */
function strengthOf(password: string): 0 | 1 | 2 | 3 | 4 {
  if (password.length === 0) return 0;
  if (password.length < PASSWORD_MIN) return 1;
  if (passwordPolicyError(password) !== null) return 2;
  if (password.length < 16) return 3;
  return 4;
}

/** Adopt a successful token response: install the session, hand the keys
 *  to the vault (which zeroizes the master key), or wipe everything. */
type AdoptionResult = "ok" | "therapist-role" | "invalid-response";
function adoptSession(keys: PatientKeys, token: TokenResponse, username: string, onSuccess: (s: LoginSuccess) => void): AdoptionResult {
  if (token.role !== "user") {
    // A therapist account cannot use the patient app — fail closed, and
    // leave nothing behind. (The v2 path pre-installs the session for the
    // envelope fetch — C-1, 2026-09-28 — so it must be torn down here too.)
    zeroize(keys.authKey, keys.dataKey, keys.masterKey);
    vault.lock();
    clearSession();
    return "therapist-role";
  }
  if (!USER_ID_PATTERN.test(token.user_id)) {
    // A hostile or broken server returned an account id outside the
    // contract — refuse it before it can reach the vault owner binding,
    // AAD contexts, or storage keys, and leave nothing behind.
    zeroize(keys.authKey, keys.dataKey, keys.masterKey);
    vault.lock();
    clearSession();
    return "invalid-response";
  }
  // expires_in rides along (audit 2026-09-26 LOW): the client schedules the
  // proactive lockDown slightly before the token dies, instead of
  // discovering expiry as a 401 mid-write.
  setSession(token.token, token.user_id, username, token.expires_in);
  vault.unlock(keys, token.user_id); // zeroizes masterKey
  onSuccess({ userId: token.user_id, username });
  return "ok";
}

/** v2 unlock half (2026-09-26): a key_scheme "v2" account's data key is
 *  NOT the HKDF data label — it is the random key inside the envelope.
 *  Fetch the envelope, unwrap it under the SAME master the login verifier
 *  proved, and swap it in for the (now wrong) derived label. Any failure
 *  leaves NOTHING behind: no session, no keys — an envelope that does not
 *  open under the just-proven password is a tampered or inconsistent
 *  server state, never something to paper over with the v1 derivation.
 *
 *  2026-09-28 audit (LOW, mobile keyScheme.ts parity): the unwrap HONORS
 *  the envelope's declared kdf_params — when the account declares a
 *  NON-default pbkdf2-sha256 iteration count, the KEK master is
 *  re-derived at exactly that count (the params and the KEK from one
 *  source); when the params name an algorithm this build cannot derive
 *  (argon2id — no native WebCrypto Argon2), the answer is the explicit
 *  unsupported-params outcome so the caller says THAT, never a
 *  misleading invalid-credentials-shaped envelope failure. The pre-login
 *  salt lookup deliberately does not echo params (backend existence
 *  oracle), so the verifier-side derive keeps the pinned default — the
 *  declared params are honored the moment they become visible. */
type EnvelopeAdoption = "ok" | "unsupported-params" | "failed";
async function adoptEnvelopeDataKey(
  password: string,
  keys: PatientKeys,
  saltB64: string,
  username: string,
): Promise<EnvelopeAdoption> {
  try {
    const envelope = await api.keyEnvelope();
    if (envelope.key_scheme !== "v2" || typeof envelope.wrapped_data_key !== "string") {
      throw new Error("not a v2 envelope");
    }
    // The envelope's salt must be the salt the master key was derived from
    // (a mismatched server answer cannot open the envelope by construction).
    if (envelope.salt !== saltB64) {
      throw new Error("envelope salt mismatch");
    }
    const params = validateKdfParams(envelope.kdf_params);
    if (params.algorithm !== "pbkdf2-sha256") {
      zeroize(keys.authKey, keys.dataKey, keys.masterKey);
      vault.lock();
      return "unsupported-params";
    }
    const salt = fromBase64(saltB64);
    // The declared count differs from the verifier-side derive: re-derive
    // the master AT the declared count (mobile's unwrapSessionDataKey
    // rule). The re-derivation is zeroized as soon as the KEK consumed it.
    let master: Bytes = keys.masterKey;
    let rederived: Bytes | null = null;
    if (params.iterations !== KDF_ITERATIONS) {
      rederived = await deriveMasterKey(password, salt, params.iterations);
      master = rederived;
    }
    let unwrapped: Bytes;
    try {
      unwrapped = await unwrapEnvelope(master, salt, username, envelope.wrapped_data_key, params);
    } finally {
      if (rederived) zeroize(rederived);
    }
    zeroize(salt, keys.dataKey);
    keys.dataKey = unwrapped;
    return "ok";
  } catch {
    zeroize(keys.authKey, keys.dataKey, keys.masterKey);
    vault.lock();
    return "failed";
  }
}

export function LoginView(props: { onSuccess: (success: LoginSuccess) => void }): React.JSX.Element {
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  // The DPIA-required age gate (clinical review 2026-09-27): an honest
  // self-declaration — the register action stays disabled until the box
  // is ticked. Nothing is stored beyond the existing registration flow
  // (no extra data, no extra request): the checkbox is UI state only,
  // reset with the other fields on a mode switch.
  const [ageConfirmed, setAgeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const switchMode = (next: "signin" | "register"): void => {
    setMode(next);
    setPassword("");
    setConfirm("");
    setAgeConfirmed(false);
    setError("");
  };

  const describeError = (err: unknown): string => {
    if (err instanceof ApiError) {
      if (err.code === "invalid_credentials") return t("login.invalidCredentialsWeb");
      if (mode === "register" && err.code === "conflict") return t("login.usernameTakenWeb");
      if (err.code === "rate_limited" && err.retryAfterMs !== undefined) {
        const seconds = Math.max(1, Math.round(err.retryAfterMs / 1000));
        return t("login.rateLimitedWeb", { seconds });
      }
      return displayError(err, t("login.genericWeb"));
    }
    return t("login.genericWeb");
  };

  const submit = async (): Promise<void> => {
    setError("");
    if (!USERNAME_PATTERN.test(username)) {
      setError(t("login.usernameRuleWeb"));
      return;
    }
    if (mode === "register") {
      // The age gate's own guard (defense-in-depth under the disabled
      // button — a synthetic submit path cannot skip the declaration).
      if (!ageConfirmed) {
        setError(t("login.ageGateNeeded"));
        return;
      }
      const policy = passwordPolicyError(password);
      if (policy) {
        setError(policy);
        return;
      }
      if (confirm !== password) {
        setError(t("login.pwMismatchWeb"));
        return;
      }
    } else if (password.length === 0) {
      setError(t("login.enterPwWeb"));
      return;
    }
    setBusy(true);
    try {
      if (mode === "signin") {
        const { salt } = await auth.saltFor(username);
        const keys = await derivePatientKeys(await deriveMasterKey(password, fromBase64(salt)));
        let token: TokenResponse;
        try {
          token = await auth.login(username, toBase64(keys.authKey));
        } catch (err) {
          zeroize(keys.authKey, keys.dataKey, keys.masterKey);
          throw err;
        }
        // v2 accounts swap the derived data label for the unwrapped random
        // key BEFORE adoption; v1 (or a key_scheme-less legacy backend)
        // keeps deriving locally — exactly the pre-2026-09-26 bytes.
        // 2026-09-28 audit C-1: the envelope fetch rides the session'd
        // request core, which refuses to run without an installed session
        // — and adoptSession (which installs it) ran AFTER the fetch. On
        // every fresh page load the fetch threw "not signed in" before any
        // HTTP request left the tab and v2 sign-in dead-ended. The session
        // is installed FIRST now; every failure path below rolls it back
        // so nothing outlives a refused login.
        if (token.key_scheme === "v2") {
          setSession(token.token, token.user_id, username, token.expires_in);
          const adoption = await adoptEnvelopeDataKey(password, keys, salt, username);
          if (adoption !== "ok") {
            clearSession();
            setError(t(adoption === "unsupported-params" ? "login.kdfUnsupportedWeb" : "login.envelopeUnlockWeb"));
            return;
          }
        }
        const adoption = adoptSession(keys, token, username, props.onSuccess);
        if (adoption === "therapist-role") {
          setError(t("login.therapistRoleWeb"));
          return;
        }
        if (adoption === "invalid-response") {
          setError(t("login.invalidResponseWeb"));
          return;
        }
      } else {
        const saltBytes = randomBytes(16);
        const saltB64 = toBase64(saltBytes);
        const keys = await derivePatientKeys(await deriveMasterKey(password, saltBytes));
        let derivedDataKey: Bytes | null = keys.dataKey;
        let token: TokenResponse;
        try {
          // v2 DEFAULT for new accounts (2026-09-26): the data key is a
          // random 32 bytes wrapped under the password-derived KEK — the
          // derived data label is drawn only to be discarded (the master
          // key still feeds the auth verifier and, for v1 servers, the
          // legacy path). Registration carries kdf_params + the 60-byte
          // wrapped_data_key together.
          const envelope = await createRegistrationEnvelope(keys.masterKey, saltBytes, username);
          // 2026-09-28 audit (LOW): the REGISTER RESPONSE is the only
          // authority on which scheme was stored. Hold the derived v1
          // label until the server ECHOES key_scheme "v2" — a backend
          // that ignored the envelope fields (older server, hostile
          // mirror) stored no wrapped_data_key, and adopting the random
          // key anyway would seal every entry under a key no unlock path
          // can ever reproduce. The login path's documented ambiguity
          // defense, mirrored here.
          keys.dataKey = envelope.dataKey;
          token = await auth.register(username, saltB64, toBase64(keys.authKey), MINIMUM_AGE_ATTESTATION, {
            kdfParams: envelope.kdfParams as unknown as Record<string, unknown>,
            wrappedDataKeyB64: envelope.wrappedDataKeyB64,
          });
          if (token.key_scheme === "v2") {
            zeroize(derivedDataKey); // the derived label is dead weight now
          } else {
            // No v2 echo: v1 semantics — restore the derived label and
            // discard the random key the server never stored.
            zeroize(keys.dataKey);
            keys.dataKey = derivedDataKey;
          }
          derivedDataKey = null; // erased or transferred back to the owned key set
        } catch (err) {
          zeroize(keys.authKey, keys.dataKey, keys.masterKey, derivedDataKey);
          throw err;
        }
        const adoption = adoptSession(keys, token, username, props.onSuccess);
        if (adoption === "therapist-role") {
          setError(t("login.therapistRoleWeb"));
          return;
        }
        if (adoption === "invalid-response") {
          setError(t("login.invalidResponseWeb"));
          return;
        }
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  const strength = strengthOf(password);
  const strengthLabel = strength === 0 ? "" : t(`login.strength${strength}`);

  return (
    <div className="login-wrap">
      <div className="login-hero">
        <Logo size={56} />
        <span className="login-hero__title">Fathom</span>
        <span className="login-hero__tagline">{t("login.brandTagline")}</span>
      </div>
      <Card title={mode === "signin" ? t("login.webSignInTitle") : t("login.webRegisterTitle")}>
        {/* A real form: Enter submits (the old card omitted it). The
            visible action stays a plain Button; this hidden native submit
            is what Enter activates — never tabbable, never clickable. */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy) void submit();
          }}
          style={{ display: "flex", flexDirection: "column", gap: "var(--space-3)" }}
        >
          <button type="submit" tabIndex={-1} aria-hidden="true" style={{ position: "absolute", left: -9999, width: 1, height: 1, opacity: 0 }} />
          <Field label={t("login.webUsername")} value={username} onChange={setUsername} autoComplete="username" placeholder={t("login.webUsernamePlaceholder")} />
          {/* No password placeholder: bullet-run placeholders read as a
              SAVED password at a glance (audit 2026-09-26 fix) — the
              visible label is the only cue. */}
          <Field label={t("login.webPassword")} value={password} onChange={setPassword} type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} />
          {mode === "register" && (
            <>
              {/* The meter rates the PASSWORD field, so it sits directly
                  beneath it — under "Confirm password" it looked like
                  feedback for the wrong input (audit 2026-09-26 fix). */}
              {strength > 0 && (
                <div className="strength" role="status" aria-label={t("login.strengthA11y", { level: strengthLabel })}>
                  <span className={`strength__bar${strength === 1 ? " strength__bar--1" : strength === 2 ? " strength__bar--2" : strength === 3 ? " strength__bar--3" : " strength__bar--4"}`} />
                  <span className={`strength__bar${strength >= 2 ? strength === 2 ? " strength__bar--2" : strength === 3 ? " strength__bar--3" : " strength__bar--4" : ""}`} />
                  <span className={`strength__bar${strength >= 3 ? (strength === 3 ? " strength__bar--3" : " strength__bar--4") : ""}`} />
                  <span className={`strength__bar${strength === 4 ? " strength__bar--4" : ""}`} />
                  <span className="note note--muted" style={{ whiteSpace: "nowrap" }}>{strengthLabel}</span>
                </div>
              )}
              <Field label={t("login.webConfirm")} value={confirm} onChange={setConfirm} type="password" autoComplete="new-password" />
              <Note>{t("login.webRegisterNote")}</Note>
              {/* DPIA age gate (clinical review 2026-09-27): an honest
                  self-declaration — 18+, per the DPIA's design (per-
                  jurisdiction guardian consent is an operator/policy
                  matter, not an app control). The server records only the
                  versioned confirmation and its server-side timestamp. */}
              <Checkbox checked={ageConfirmed} onChange={setAgeConfirmed}>{t("login.ageGate")}</Checkbox>
            </>
          )}
          <ErrorBanner message={error} />
          <Button
            label={busy ? t("settings.working") : mode === "signin" ? t("login.webSignInTitle") : t("login.webCreateJournal")}
            onPress={() => void submit()}
            disabled={busy || (mode === "register" && !ageConfirmed)}
            block
          />
          <Button label={mode === "signin" ? t("login.webCreateAccount") : t("login.webHaveAccount")} onPress={() => switchMode(mode === "signin" ? "register" : "signin")} small variant="ghost" block />
        </form>
        <Note tone="muted">{t("login.webNeverLeaves")}</Note>
      </Card>
    </div>
  );
}
