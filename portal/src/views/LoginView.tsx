/**
 * Login / therapist registration. The password NEVER leaves this form:
 * it is stretched into the auth key (sent) and the portal wrap KEK (kept
 * in memory) exactly like the patient apps.
 */
import { useState } from "react";
import { auth, ApiError, setSession, type TokenResponse } from "../api";
import { deriveMasterKey, derivePortalKeys, fromBase64, generateTherapistKeyPair, sealPrivateKeyForUpload } from "../crypto";
import { Button, Card, ErrorBanner, Field, Note, theme } from "../ui";
import { currentOrigin } from "../platform";

export interface PortalKeys {
  username: string;
  userId: string;
  wrapKek: Uint8Array<ArrayBuffer>;
  noteKey: Uint8Array<ArrayBuffer>;
}

export function normalizeBaseUrl(candidate: string): string {
  const trimmed = candidate.trim().replace(/\/+$/, "");
  if (trimmed === "") return "";
  try {
    const url = new URL(trimmed);
    return url.origin + url.pathname.replace(/\/+$/, "");
  } catch {
    return "";
  }
}

export function LoginView(props: { onReady: (keys: PortalKeys, token: TokenResponse, baseUrl: string) => void }): React.JSX.Element {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [server, setServer] = useState(currentOrigin());
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [password2, setPassword2] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const baseUrl = normalizeBaseUrl(server);

  const signIn = async () => {
    setBusy(true);
    setError("");
    try {
      const { salt } = await auth.saltFor(baseUrl, username);
      const master = await deriveMasterKey(password, fromBase64(salt));
      const keys = await derivePortalKeys(master);
      const token = await auth.login(baseUrl, username, keys.authKeyB64);
      if (token.role !== "therapist") {
        throw new ApiError(403, "this is a patient account — the portal is for therapist accounts");
      }
      setSession(token.token, baseUrl);
      props.onReady(
        { username, userId: token.user_id, wrapKek: keys.wrapKek, noteKey: keys.noteKey },
        token,
        baseUrl,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  const register = async () => {
    if (password !== password2) {
      setError("the two passwords do not match");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const salt = btoa(String.fromCharCode(...saltBytes));
      const master = await deriveMasterKey(password, saltBytes);
      const keys = await derivePortalKeys(master);
      const pair = await generateTherapistKeyPair();
      const sealed = await sealPrivateKeyForUpload(keys.wrapKek, pair.privateKeyPkcs8B64, username);      const token = await auth.registerTherapist(baseUrl, {
        username,
        salt,
        verifier: keys.authKeyB64,
        display_name: displayName || username,
        wrap_pub_key: pair.publicKeySpkiB64,
        wrap_key_blob: sealed,
      });
      setSession(token.token, baseUrl);
      props.onReady(
        { username, userId: token.user_id, wrapKek: keys.wrapKek, noteKey: keys.noteKey },
        token,
        baseUrl,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "registration failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <main style={{ backgroundColor: theme.bg, minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24 }}>
      <div style={{ width: 420, display: "flex", flexDirection: "column", gap: 14 }}>
        <h1 style={{ color: theme.text, fontSize: 22, margin: 0 }}>MindPattern · Therapist portal</h1>
        <Card title={mode === "login" ? "Sign in" : "Create a therapist account"}>
          {mode === "register" && (
            <>
              <Field label="Your name (shown to patients)" value={displayName} onChange={setDisplayName} placeholder="Dr. Jane Omega" />
              <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" />
            </>
          )}
          {mode === "login" && <Field label="Username" value={username} onChange={setUsername} placeholder="dromega" />}
          <Field label="Password" value={password} onChange={setPassword} type="password" />
          {mode === "register" && (
            <Field label="Repeat password" value={password2} onChange={setPassword2} type="password" />
          )}
          <Field label="Server" value={server} onChange={setServer} placeholder="https://your-server" />
          <ErrorBanner message={error} />
          {mode === "login" ? (
            <>
              <Button label={busy ? "Signing in…" : "Sign in"} onPress={signIn} disabled={busy || !username || !password || !baseUrl} />
              <Button label="Create a therapist account instead" small onPress={() => { setMode("register"); setError(""); }} disabled={busy} />
            </>
          ) : (
            <>
              <Button
                label={busy ? "Creating…" : "Create account"}
                onPress={register}
                disabled={busy || !username || !password || !baseUrl}
              />
              <Button label="Back to sign in" small onPress={() => { setMode("login"); setError(""); }} disabled={busy} />
            </>
          )}
          <Note>
            Your password never leaves this page: the server stores only a hash of a derived key, and
            your sharing key is decryptable only with your password.
          </Note>
        </Card>
      </div>
    </main>
  );
}
