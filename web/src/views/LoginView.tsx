/**
 * Sign-in / registration — the zero-knowledge entry. Everything is derived
 * on-device: the password NEVER leaves this page; only the auth subkey
 * crosses the wire as the login verifier (the same contract as the mobile
 * app, pinned by shared/vectors.json). Keys land in the memory-only vault;
 * the master key is zeroized the moment the subkeys exist, and EVERY
 * failure path wipes all three.
 */
import { useState } from "react";
import { ApiError, auth, setSession, type TokenResponse } from "../api/client";
import { deriveMasterKey, fromBase64, toBase64, zeroize } from "../crypto/core";
import { derivePatientKeys, type PatientKeys } from "../crypto/keys";
import { randomBytes } from "../platform";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Field, Note } from "../ui";

/** Mirrors the backend's USERNAME_PATTERN (schemas.py): honest client-side
 *  validation so the server's validation_error never surprises anyone. */
const USERNAME_PATTERN = /^[a-zA-Z0-9_.-]{3,64}$/;
/** Server account ids are 32-hex (uuid4().hex). The login response is
 * hostile-server-controllable text like any other server payload: a
 * malformed id must never reach the vault owner binding or storage keys
 * (mobile L-7 parity, fix W-5, audit 2026-09-25). */
const USER_ID_PATTERN = /^[0-9a-f]{32}$/;
const PASSWORD_MIN = 12;

export interface LoginSuccess {
  userId: string;
  username: string;
}

/** On-device password policy (identical to mobile, incl. its L-6 shape
 * rules): 12+ characters, below 16 at least three of the four character
 * classes, and never the trivially-guessable families — a zero-knowledge
 * design leaves the server only the derived verifier, so the POLICY is
 * entirely client-side (fix W-3, audit 2026-09-25). These are the
 * families the mobile on-device unlock oracle would otherwise crack in
 * minutes on a stolen phone. */
const COMMON_PASSWORD_WORDS = [
  "password", "qwerty", "123456", "12345678", "123456789", "letmein",
  "iloveyou", "welcome", "admin", "monkey", "dragon", "sunshine",
  "princess", "football", "baseball", "master", "abc123", "111111",
  "mindpattern", "journal",
];

export function passwordPolicyError(password: string): string | null {
  if (password.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`;
  if (password.length < 16) {
    const variety =
      (/[a-z]/.test(password) ? 1 : 0)
      + (/[A-Z]/.test(password) ? 1 : 0)
      + (/[0-9]/.test(password) ? 1 : 0)
      + (/[^a-zA-Z0-9]/.test(password) ? 1 : 0);
    if (variety < 3) return "Use at least three of: lowercase, uppercase, digits, symbols (or 16+ characters).";
  }
  const lowered = password.toLowerCase();
  if (COMMON_PASSWORD_WORDS.some((word) => lowered.includes(word))) {
    return "That password is too common or predictable — choose something unique.";
  }
  if (/^(.)\1+$/.test(password)) {
    return "That password is too common or predictable — choose something unique.";
  }
  if (/^(0123|1234|2345|3456|4567|5678|6789|qwer|asdf|zxcv)/i.test(password)) {
    return "That password is too common or predictable — choose something unique.";
  }
  return null;
}

/** Adopt a successful token response: install the session, hand the keys
 * to the vault (which zeroizes the master key), or wipe everything. */
type AdoptionResult = "ok" | "therapist-role" | "invalid-response";
function adoptSession(keys: PatientKeys, token: TokenResponse, username: string, onSuccess: (s: LoginSuccess) => void): AdoptionResult {
  if (token.role !== "user") {
    // A therapist account cannot use the patient app — fail closed, and
    // leave nothing behind.
    zeroize(keys.authKey, keys.dataKey, keys.masterKey);
    vault.lock();
    return "therapist-role";
  }
  if (!USER_ID_PATTERN.test(token.user_id)) {
    // A hostile or broken server returned an account id outside the
    // contract — refuse it before it can reach the vault owner binding,
    // AAD contexts, or storage keys, and leave nothing behind.
    zeroize(keys.authKey, keys.dataKey, keys.masterKey);
    vault.lock();
    return "invalid-response";
  }
  setSession(token.token, token.user_id, username);
  vault.unlock(keys, token.user_id); // zeroizes masterKey
  onSuccess({ userId: token.user_id, username });
  return "ok";
}

export function LoginView(props: { onSuccess: (success: LoginSuccess) => void }): React.JSX.Element {
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const switchMode = (next: "signin" | "register"): void => {
    setMode(next);
    setPassword("");
    setConfirm("");
    setError("");
  };

  const describeError = (err: unknown): string => {
    if (err instanceof ApiError) {
      if (err.code === "rate_limited" && err.retryAfterMs !== undefined) {
        const seconds = Math.max(1, Math.round(err.retryAfterMs / 1000));
        return `Too many attempts — try again in about ${seconds}s.`;
      }
      return err.message;
    }
    return "Something went wrong — try again.";
  };

  const submit = async (): Promise<void> => {
    setError("");
    if (!USERNAME_PATTERN.test(username)) {
      setError("Username: 3–64 characters — letters, digits, dot, dash, underscore.");
      return;
    }
    if (mode === "register") {
      const policy = passwordPolicyError(password);
      if (policy) {
        setError(policy);
        return;
      }
      if (confirm !== password) {
        setError("The two passwords do not match.");
        return;
      }
    } else if (password.length === 0) {
      setError("Enter your password.");
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
        const adoption = adoptSession(keys, token, username, props.onSuccess);
        if (adoption === "therapist-role") {
          setError("This is a therapist account — use the therapist portal instead.");
          return;
        }
        if (adoption === "invalid-response") {
          setError("Sign-in failed — the server sent an invalid response. Try again.");
          return;
        }
      } else {
        const saltB64 = toBase64(randomBytes(16));
        const keys = await derivePatientKeys(await deriveMasterKey(password, fromBase64(saltB64)));
        let token: TokenResponse;
        try {
          token = await auth.register(username, saltB64, toBase64(keys.authKey));
        } catch (err) {
          zeroize(keys.authKey, keys.dataKey, keys.masterKey);
          throw err;
        }
        const adoption = adoptSession(keys, token, username, props.onSuccess);
        if (adoption === "therapist-role") {
          setError("This is a therapist account — use the therapist portal instead.");
          return;
        }
        if (adoption === "invalid-response") {
          setError("Sign-in failed — the server sent an invalid response. Try again.");
          return;
        }
      }
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title={mode === "signin" ? "Sign in" : "Create your journal"}>
      <Field label="Username" value={username} onChange={setUsername} autoComplete="username" placeholder="e.g. quiet.morning" />
      <Field label="Password" value={password} onChange={setPassword} type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} />
      {mode === "register" && (
        <>
          <Field label="Confirm password" value={confirm} onChange={setConfirm} type="password" autoComplete="new-password" />
          <Note>12+ characters (16+, or three character classes, keeps it strong). If you forget it, nobody can recover it — that is the point.</Note>
        </>
      )}
      <ErrorBanner message={error} />
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <Button label={busy ? "Working…" : mode === "signin" ? "Sign in" : "Create journal"} onPress={() => void submit()} disabled={busy} />
        <Button label={mode === "signin" ? "Create an account" : "I have an account"} onPress={() => switchMode(mode === "signin" ? "register" : "signin")} small />
      </div>
      <Note tone="muted">Your password never leaves this device. Only a derived verifier is sent — the server cannot read your journal.</Note>
    </Card>
  );
}
