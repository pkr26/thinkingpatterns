/**
 * Onboarding / login. The password exists in component state for the minimum
 * time: keys are derived, the master key is zeroized, and only the auth key
 * ever crosses the network. The password itself is stored nowhere — on
 * failure every derived buffer is zeroized before the retry.
 *
 * REGISTRATION HONESTY (audit fix): there is NO password reset — a forgotten
 * password means permanent journal loss (zero-knowledge cuts both ways).
 * Registration says so in plain sight, asks for the password twice, and
 * shows a simple strength hint (length + variety heuristic, on-device only).
 *
 * PASSWORD POLICY: identical to the therapist portal (portal/src/views/
 * LoginView.tsx) so both clients share one contract — and this password
 * derives the MORE valuable key, the patient data key. Minimum 12
 * characters; at 12–15 characters, at least three of the four character
 * types. A 16+ character passphrase is accepted without symbol rules.
 *
 * Errors never leak raw server text: ApiError maps to calm copy by status.
 */
import React, { useState } from "react";
import {
  Alert,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Switch,
  Text,
  TextInput,
  View,
} from "react-native";
import qcrypto from "react-native-quick-crypto";
import { api, ApiError, getBaseUrl } from "../api/client";
import { deriveKeysAsync } from "../crypto/MindPatternCrypto";
import type { Keys } from "../crypto/MindPatternCrypto";
import { KDF_ITERATIONS, zeroize } from "../crypto/kdf";
import { buildRegistrationEnvelope, cachedEnvelope, cacheEnvelope, fetchEnvelope, unwrapSessionDataKey, type EnvelopeInfo } from "../keyScheme";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof } from "../unlockProof";
import { queueOnboarding } from "../onboarding";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";
import { t as tr } from "../strings";

/** Calm, domain-aware copy for a failed sign-in/registration. */
function signInFailureCopy(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return tr("login.badCredentials");
    if (err.status === 409) return tr("login.usernameTaken");
  }
  return requestFailureCopy(err);
}

/** On-device strength heuristic: length + character variety. No zxcvbn, no
 *  network — just enough to nudge away from "password123". The returned
 *  label/hint are catalog lookups (rendered verbatim on screen). */
export function passwordStrength(password: string): { label: string; hint: string } {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (score <= 2) return { label: tr("login.strength.weak"), hint: tr("login.strengthWeakHint") };
  if (score <= 4) return { label: tr("login.strength.fair"), hint: tr("login.strengthFairHint") };
  return { label: tr("login.strength.strong"), hint: "" };
}

/**
 * Registration password policy — mirrors the portal's passwordPolicyError
 * exactly (same thresholds, same character classes). Returns "" when the
 * password is acceptable; otherwise calm copy for the alert.
 */
export function passwordPolicyError(password: string): string {
  if (password.length < 12) return tr("login.policyMin");
  const classes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)]
    .filter(Boolean).length;
  if (password.length < 16 && classes < 3) {
    return tr("login.policyVariety");
  }
  // L-6 (2026-09-20): shape rules the server can never enforce — a
  // zero-knowledge design leaves it only the derived verifier, so the
  // password POLICY is entirely client-side. These reject the trivially
  // guessable families the on-device unlock oracle (unlockProof) would
  // otherwise crack in minutes on a stolen phone.
  const lowered = password.toLowerCase();
  const commonWords = [
    "password", "qwerty", "123456", "12345678", "123456789", "letmein",
    "iloveyou", "welcome", "admin", "monkey", "dragon", "sunshine",
    "princess", "football", "baseball", "master", "abc123", "111111",
    "mindpattern", "journal",
  ];
  if (commonWords.some((word) => lowered.includes(word))) return tr("login.policyCommon");
  if (/^(.)\1+$/.test(password)) return tr("login.policyCommon"); // one repeated character
  if (/^(0123|1234|2345|3456|4567|5678|6789|qwer|asdf|zxcv)/i.test(password)) {
    return tr("login.policyCommon");
  }
  return "";
}

export function LoginScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { refreshActiveDays, markLoggedIn } = useSession();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  // Stryker disable next-line StringLiteral: dead initializer — register mode is reachable only through the toggle (which clears confirm in the same batch) and login mode never reads confirm
  const [confirm, setConfirm] = useState("");
  // AGE GATE (2026-09-27, clinical): registration requires an explicit
  // "I am 18 or older" self-declaration. It gates the Create-account button
  // AND the submit path (defense in depth — a keyboard submit or a bypassed
  // disabled state must never reach the network). Nothing is STORED: the
  // declaration is an act of the moment, not account data (no date of
  // birth, no attestation record — the gate is the checkbox, once, here).
  const [ageConfirmed, setAgeConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  // M-3 (2026-09-20): the first origin this device ever authenticated
  // against is pinned; a DIFFERENT selected server renders a prominent
  // warning BEFORE the password is typed — the login credential is the
  // derived auth key with no reset path, so typing it at a phished
  // "support server" must be a visibly deliberate act.
  const [serverChanged, setServerChanged] = useState(false);
  const [serverUrl, setServerUrl] = useState("");

  React.useEffect(() => {
    void api.originPinChanged().then(setServerChanged).catch(() => setServerChanged(false));
    void getBaseUrl().then((url) => setServerUrl(url ?? "")).catch(() => {});
  }, []);

  const submit = async () => {
    const name = username.trim();
    if (!name || !password || busy) return;
    if (mode === "register") {
      // The age gate precedes every other check: no policy alerts, no
      // network, nothing — until the 18+ declaration is made.
      if (!ageConfirmed) return;
      const policyError = passwordPolicyError(password);
      if (policyError) {
        Alert.alert(
          password.length < 12 ? tr("login.policyShortTitle") : tr("login.policyVarietyTitle"),
          policyError,
        );
        return;
      }
      if (password !== confirm) {
        Alert.alert(tr("login.mismatchTitle"), tr("login.mismatchBody"));
        return;
      }
    }
    setBusy(true);
    let derived: Keys | null = null;
    /** v2 sessions: the data key that actually overrides derived.dataKey —
     *  a fresh random key at registration, the unwrapped envelope key at
     *  login. Held here so the catch can zeroize it if the flow dies before
     *  the vault takes ownership. */
    let sessionDataKey: Buffer | null = null;
    // L-65 (2026-09-20 audit): once api.register resolves, the ACCOUNT
    // EXISTS on the server no matter what happens next. A later failure
    // (session write, unlock proof, salt cache — typically a connection
    // drop mid-flow) used to surface as a generic "couldn't create
    // account", stranding the user on a register form whose retry would
    // now 409 "username taken". The failure copy says the honest next
    // step: switch to sign-in with the credentials that just worked.
    let accountCreated = false;
    try {
      // Stryker disable next-line StringLiteral: dead initializer — both branches assign body.user_id before the only read at vault.unlock
    let verifiedUserId = "";
      if (mode === "register") {
        // Buffer.from() copies: quick-crypto's Buffer type differs from
        // node's in the .d.ts, but the bytes are identical.
        const salt = Buffer.from(qcrypto.randomBytes(16));
        // Async derivation: no 100–400ms JS-thread freeze mid-flow.
        derived = await deriveKeysAsync(password, salt);
        // v2 KEY ENVELOPE (2026-09-26) — the default for every NEW account:
        // a fresh RANDOM data key, wrapped under a KEK derived from the
        // same PBKDF2 master key that produced the login verifier. A later
        // password change rewraps this envelope in O(1) instead of
        // re-encrypting the whole journal, and the password never again
        // directly derives the storage key.
        const envelope = await buildRegistrationEnvelope(password, salt, name);
        sessionDataKey = envelope.dataKey;
        const body = await api.register(
          name,
          salt.toString("base64"),
          derived.authKey.toString("base64"),
          envelope.kdfParams,
          envelope.wrappedB64,
        );
        accountCreated = true;
        await api.setSession(body.token, body.user_id, name);
        // The account was created on THIS device: seal the offline-unlock
        // proof under the RANDOM data key right away.
        await storeUnlockProof(envelope.dataKey, body.user_id);
        await api.cacheSalt(name, salt.toString("base64"));
        await cacheEnvelope(name, {
          scheme: "v2",
          saltB64: salt.toString("base64"),
          kdfParams: envelope.kdfParams,
          wrappedB64: envelope.wrappedB64,
        }).catch(() => {});
        verifiedUserId = body.user_id;
      } else {
        const { salt: saltB64 } = await api.saltFor(name);
        // Cache the (public, origin-bound) salt so a later cold-restart
        // unlock can derive keys even when the network is unreachable.
        await api.cacheSalt(name, saltB64);
        derived = await deriveKeysAsync(password, Buffer.from(saltB64, "base64"));
        const body = await api.login(name, derived.authKey.toString("base64"));
        await api.setSession(body.token, body.user_id, name);
        // KEY SCHEME (2026-09-26): v2 accounts fetch the envelope and
        // unwrap LOCALLY (the username-bound AAD means this blob opens only
        // under this account's password); v1 accounts keep the derived
        // data key, byte-for-byte as before. The sealed proof below is
        // stored under whichever key won.
        const fetched = await fetchEnvelope();
        // Re-audit 2026-09-27 (M): when the account is v2 but the envelope
        // can be NEITHER fetched ("invalid" — the server answered with a
        // shape this client refuses; "unreachable" — the endpoint failed)
        // NOR read from this device's cache, the old fall-through unlocked
        // the vault on the v1-DERIVED data key. Every entry written that
        // session sealed under a key the account's real (envelope) key can
        // never open — silent, permanent corruption. REFUSE the session
        // instead: the password was accepted, so the honest copy says the
        // key could not be verified and NOTHING was changed. ("legacy" — a
        // 404 from a pre-envelope server — cannot host a v2 account and
        // keeps v1 semantics.)
        // independent audit 2026-09-27 (P2): the refusal now also covers the
        // STALE-v1-MARKER case. Only a definitive server answer ("ok" v1,
        // or "legacy") or a cached v2 ENVELOPE with material may authorize
        // the v1 path; after a FAILED fetch, a cached v1 marker is a scheme
        // hint from an earlier session — routing on it would re-seal the
        // proof under the v1-derived key, safe today only because v1→v2
        // wraps the SAME data key and a silent wrong-key write under any
        // future scheme rotation. Fail closed with honest retry copy.
        const envelope: EnvelopeInfo | null =
          fetched.status === "ok" ? fetched.envelope : await cachedEnvelope(name);
        if (fetched.status !== "ok" && fetched.status !== "legacy"
          && (envelope === null || envelope.scheme !== "v2")) {
          throw new Error(tr(fetched.status === "invalid" ? "login.envelopeUnrecognized" : "unlock.schemeUnconfirmed"));
        }
        if (envelope !== null && envelope.scheme === "v2") {
          const unwrapped = await unwrapSessionDataKey({
            password,
            username: name,
            envelope,
            derivedMaster: { key: derived.masterKey, saltB64, iterations: KDF_ITERATIONS },
          });
          if (!unwrapped.ok) {
            // The password was just accepted ONLINE, so a tamper failure is
            // not "wrong password" — the envelope does not belong to this
            // password on this server. Fail closed with our own local copy
            // (a plain Error passes through requestFailureCopy verbatim).
            throw new Error(tr("login.envelopeFailed"));
          }
          sessionDataKey = unwrapped.dataKey;
          await storeUnlockProof(unwrapped.dataKey, body.user_id);
          await cacheEnvelope(name, envelope).catch(() => {});
        } else {
          // Login SUCCEEDED and the scheme answer is definitive (fetched
          // v1, or a legacy 404 server): seal the proof that offline
          // unlocks will be checked against (see UnlockScreen).
          await storeUnlockProof(derived.dataKey, body.user_id);
          // A fetched v1 envelope is cached so the next OFFLINE unlock
          // knows the sealed-proof path is the right one without another
          // round-trip. (This branch is unreachable with a mere cached v1
          // marker after a failed fetch — the refusal above already threw.)
          if (envelope !== null) await cacheEnvelope(name, envelope).catch(() => {});
        }
        verifiedUserId = body.user_id;
      }
      // The vault records WHICH account these keys belong to — key-shipping
      // operations (processing sessions) verify that binding. For v2 the
      // data key is the envelope's RANDOM key; the (now unused) v1 data
      // label is zeroized immediately.
      if (sessionDataKey !== null && derived !== null) {
        vault.unlock(
          { masterKey: derived.masterKey, authKey: derived.authKey, dataKey: sessionDataKey },
          verifiedUserId || undefined,
        );
        zeroize(derived.dataKey);
      } else {
        vault.unlock(derived!, verifiedUserId || undefined); // takes ownership; zeroizes the master key
      }
      sessionDataKey = null; // the vault owns it now
      derived = null;
      setPassword(""); // minimize the password's lifetime in memory
      setConfirm("");
      await refreshActiveDays();
      // A brand-new account routes through first-run onboarding (once — see
      // src/onboarding.ts); a plain login never does.
      if (mode === "register") queueOnboarding();
      markLoggedIn();
    } catch (err) {
      if (sessionDataKey) zeroize(sessionDataKey);
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      vault.lock();
      Alert.alert(
        mode === "register" && accountCreated
          ? tr("login.registerPartialTitle")
          : mode === "register"
            ? tr("login.registerFailedTitle")
            : tr("login.signInFailedTitle"),
        mode === "register" && accountCreated ? tr("login.registerPartialBody") : signInFailureCopy(err),
      );
    } finally {
      setBusy(false);
    }
  };

  const strength = mode === "register" && password.length > 0 ? passwordStrength(password) : null;
  // Stryker disable next-line ConditionalExpression: confirm.length > 0 implies register mode (the confirm field is register-only and every exit to login clears it), so the mode check is redundant — the same-line whole-condition mutant is killable and pinned in loginScreen.pins.test.tsx
  const mismatch = mode === "register" && confirm.length > 0 && confirm !== password;

  return (
    <KeyboardAvoidingView
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxxl, gap: t.spacing.md }]}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView
        contentContainerStyle={{ flexGrow: 1, justifyContent: "center", gap: t.spacing.md }}
        keyboardShouldPersistTaps="handled"
      >
      <Text style={[styles.title, { color: t.colors.text }]} maxFontSizeMultiplier={1.6}>
        MindPattern
      </Text>
      <Text style={[styles.subtitle, { color: t.colors.muted, fontSize: 14 }]}>
        {tr("login.subtitle")}
      </Text>
      {serverUrl !== "" && (
        <Text style={{ color: t.colors.muted, fontSize: 12 }} accessibilityLabel={tr("login.serverA11y")}>
          {tr("login.serverLabel", { server: serverUrl })}
        </Text>
      )}
      {serverChanged && (
        // Audit fix 20 (2026-09-21): t.colors.error, not a hardcoded hex —
        // the literal measured 2.89:1 on the dark bg (WCAG AA failure on a
        // security warning); the theme's error color measures 6.8:1.
        <Text style={{ color: t.colors.error, fontSize: 13 }} accessibilityLabel={tr("login.serverChangedA11y")}>
          {tr("login.serverChangedWarning")}
          {"\n"}
          <Text
            onPress={() => {
              void api.confirmCurrentOrigin().then(() => setServerChanged(false)).catch(() => {});
            }}
            style={{ fontWeight: "600", textDecorationLine: "underline" }}
          >
            {tr("login.trustThisServer")}
          </Text>
        </Text>
      )}
      <TextInput
        style={inputTheme(t)}
        placeholder={tr("login.usernamePlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        autoCapitalize="none"
        value={username}
        onChangeText={setUsername}
        accessibilityLabel={tr("login.usernameA11y")}
        textContentType="username"
        autoComplete="username"
      />
      <TextInput
        style={inputTheme(t)}
        placeholder={tr("common.passwordPlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={submit}
        accessibilityLabel={tr("common.passwordA11y")}
        textContentType={mode === "register" ? "newPassword" : "password"}
        autoComplete={mode === "register" ? "new-password" : "current-password"}
      />
      {mode === "register" && (
        <TextInput
          style={inputTheme(t)}
          placeholder={tr("login.confirmPlaceholder")}
          placeholderTextColor={t.colors.placeholder}
          secureTextEntry
          value={confirm}
          onChangeText={setConfirm}
          onSubmitEditing={submit}
          accessibilityLabel={tr("login.confirmA11y")}
          textContentType="newPassword"
          autoComplete="new-password"
        />
      )}
      {strength && (
        <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }} accessibilityLiveRegion="polite">
          {`${tr("login.strength", { label: strength.label })}${strength.hint ? ` ${strength.hint}` : ""}`}
        </Text>
      )}
      {mismatch && (
        <Text style={{ color: t.colors.error, fontSize: t.type.meta.fontSize }} accessibilityRole="alert">
          {tr("login.mismatchInline")}
        </Text>
      )}
      {mode === "register" && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("login.policyHint")}
        </Text>
      )}
      {mode === "register" && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("login.noReset")}
        </Text>
      )}
      {mode === "register" && (
        // The 18+ self-declaration (2026-09-27): a checkbox row the user
        // must actively check — never pre-ticked, never inferred. Calm copy,
        // no explanation owed beyond the statement itself.
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
          <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, flex: 1, lineHeight: 19 }}>
            {tr("login.ageConfirm")}
          </Text>
          <Switch
            value={ageConfirmed}
            onValueChange={(on) => setAgeConfirmed(on)}
            accessibilityLabel={tr("login.ageConfirmA11y")}
            accessibilityState={{ checked: ageConfirmed }}
          />
        </View>
      )}
      <PrimaryButton
        label={mode === "login" ? tr("login.signIn") : tr("login.createAccount")}
        onPress={submit}
        disabled={mode === "register" && !ageConfirmed}
        busy={busy}
      />
      <GhostButton
        label={mode === "login" ? tr("login.switchToRegister") : tr("login.switchToSignIn")}
        onPress={() => {
          setMode(mode === "login" ? "register" : "login");
          setConfirm("");
          // Re-entering register mode re-arms the declaration: a mode flip
          // must never carry a stale "18+" across contexts.
          setAgeConfirmed(false);
        }}
      />
      {/* Crisis help needs no account and no network. */}
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const inputTheme = (t: ReturnType<typeof useTheme>) => ({
  backgroundColor: t.colors.card,
  color: t.colors.text,
  borderRadius: t.radius.md,
  padding: 14,
  fontSize: 16,
});

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center" },
  title: { fontSize: 34, fontWeight: "700", textAlign: "center" },
  subtitle: { textAlign: "center", marginBottom: 24 },
});
