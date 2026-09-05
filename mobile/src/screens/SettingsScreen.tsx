/**
 * Settings: server URL, third-party analysis consent, ciphertext export,
 * re-authenticated hard delete, sign out.
 *
 * DESTRUCTIVE ACTIONS RE-AUTHENTICATE FOR REAL: "confirm with your sign-in
 * key" used to read the authKey from the unlocked vault — two taps on an
 * unattended phone deleted the journal. The delete flow and the LLM
 * consent toggle now demand the PASSWORD, re-derive the key, and compare
 * it to the vault's key before anything is sent (see reauth.ts).
 */
import React, { useEffect, useState } from "react";
import { Alert, Share, StyleSheet, Switch, Text, TextInput, TouchableOpacity, View } from "react-native";
import { api, getBaseUrl, getInsecureConsentUrl, parseServerUrl, setBaseUrl } from "../api/client";
import { vault } from "../vault";
import { useSession } from "../store";
import { verifyPasswordForVault } from "../reauth";

/** The Android share sheet dies around ~10 MB of intent payload; refuse
 *  oversized exports with an honest message instead of a silent no-op. */
const MAX_EXPORT_CHARS = 4_000_000;

type PendingAction = { kind: "llm"; enabled: boolean } | { kind: "delete" } | null;

export function SettingsScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const { signOut } = useSession();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [consentedUrl, setConsentedUrl] = useState<string | null>(null);
  const [llmAvailable, setLlmAvailable] = useState(false);
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");

  React.useEffect(() => {
    getBaseUrl().then(setUrl);
    getInsecureConsentUrl().then(setConsentedUrl);
    api.meta().then((m) => setLlmAvailable(Boolean(m?.llm_available))).catch(() => {});
    api.getLlmConsent().then((c) => setLlmEnabled(Boolean(c?.enabled))).catch(() => {});
  }, []);

  const saveUrl = async () => {
    const parsed = parseServerUrl(url);
    if (!parsed) {
      Alert.alert("Invalid URL", "Enter a full URL like https://your-server:8000");
      return;
    }
    if (parsed.insecure && consentedUrl !== parsed.url) {
      Alert.alert(
        "Insecure server",
        "This server uses plain HTTP. Everything you send — including your sign-in key — would be readable on the network. Allow insecure HTTP only for testing on a trusted network.",
        [
          { text: "Cancel", style: "cancel" },
          {
            text: "Allow insecure HTTP",
            style: "destructive",
            // Consent is per-URL and saves immediately: it can never linger
            // to bless a different cleartext server later.
            onPress: () => {
              setConsentedUrl(parsed.url);
              void setBaseUrl(parsed.url, { allowInsecure: true }).then((error) => {
                if (error) Alert.alert("Could not save server", error);
                else Alert.alert("Saved", `Server URL updated (${parsed.url}).`);
              });
            },
          },
        ],
      );
      return;
    }
    const error = await setBaseUrl(parsed.url, { allowInsecure: parsed.insecure && consentedUrl === parsed.url });
    if (error) Alert.alert("Could not save server", error);
    else Alert.alert("Saved", `Server URL updated (${parsed.url}).`);
  };

  /** Destructive flows land here FIRST — the actual action only runs after
   *  the typed password re-derives the vault's own auth key. */
  const confirmWithPassword = async () => {
    if (!pending || busy || !password) return;
    setBusy(true);
    try {
      const reauth = await verifyPasswordForVault(password);
      if (!reauth.ok) {
        const messages = {
          locked: "the vault is locked — unlock again first",
          "no-account": "no saved account on this device — sign in again",
          "wrong-password": "Wrong password.",
          offline: "cannot verify your password offline right now — try again when online",
        } as const;
        Alert.alert("Could not verify", messages[reauth.reason]);
        return;
      }
      if (pending.kind === "llm") {
        const result = await api.setLlmConsent(pending.enabled, reauth.verifierB64);
        setLlmEnabled(result.enabled);
      } else {
        await deleteAccountOnServer(reauth.verifierB64);
      }
    } catch (err) {
      Alert.alert("Could not complete", err instanceof Error ? err.message : "unknown error");
    } finally {
      setBusy(false);
      setPending(null);
      setPassword("");
    }
  };

  const deleteAccountOnServer = async (verifierB64: string) => {
    let serverDeleted = false;
    try {
      const userId = await api.getUserId();
      const username = await api.getUsername();
      await api.deleteAccount(verifierB64);
      serverDeleted = true;
      vault.lock();
      // Local cleanup is attempted in full, but a failure here must NOT be
      // reported as a failed delete (the server data is already gone and a
      // retry can never work) — the user is told the truth instead.
      try {
        const { clearQueue } = await import("../offlineQueue");
        const { clearMoodLog } = await import("../moodLog");
        const { clearRecomputeStamp } = await import("../brainSync");
        const { clearUnlockProof } = await import("../unlockProof");
        await clearQueue();
        if (userId) {
          await clearMoodLog(userId);
          await clearRecomputeStamp(userId);
          await clearUnlockProof(userId);
        }
        if (username) await api.clearCachedSalt(username);
      } catch {
        // Reported in the success dialog below.
      }
      await signOut(); // revokes tokens, clears the session
      Alert.alert(
        "Deleted",
        serverDeleted
          ? "Your account and data were deleted from the server. If anything failed to clear on this device, reinstalling the app removes the remnants."
          : "deleted",
      );
    } catch (err) {
      // The server still holds the account — keep the local session intact
      // so the user can retry instead of believing it worked.
      Alert.alert("Delete failed", err instanceof Error ? err.message : "unknown error");
    }
  };

  const exportData = async () => {
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (userId) {
        const { flushQueue } = await import("../offlineQueue");
        await flushQueue(userId).catch(() => {});
      }
      const bundle = await api.exportAccount();
      // Ciphertext bundle: decryptable with your password (tools/decrypt_export.mjs).
      const json = JSON.stringify(bundle, null, 2);
      if (json.length > MAX_EXPORT_CHARS) {
        Alert.alert(
          "Export too large",
          `Your export is ${(json.length / 1_000_000).toFixed(1)}M characters — too large for the device share sheet. Contact support for a bulk export.`,
        );
        return;
      }
      try {
        const result = (await Share.share({ title: "MindPattern export (encrypted)", message: json })) as
          | { action?: string }
          | undefined;
        if (result?.action === "dismissedAction") return; // user cancelled — quiet
        Alert.alert(
          "Exported",
          `${bundle.entries.length} entries and ${bundle.insights.length} insights (encrypted). ` +
            "Keep it safe — it is only decryptable with your password (see tools/decrypt_export.mjs).",
        );
      } catch {
        // A share failure must never look like a successful export.
        Alert.alert(
          "Export did not complete",
          "The share sheet failed or closed before anything was shared. Nothing left the device.",
        );
      }
    } catch (err) {
      Alert.alert("Export failed", err instanceof Error ? err.message : "unknown error");
    } finally {
      setBusy(false);
    }
  };

  const deleteEverything = () => {
    Alert.alert(
      "Delete everything?",
      "All entries, patterns and your account will be permanently deleted from the server. " +
        "Your local encrypted queue is also wiped. This cannot be undone. You will be asked for your password.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Continue",
          style: "destructive",
          onPress: () =>
            Alert.alert("Final confirmation", "Deleting is irreversible. You will be asked for your password next.", [
              { text: "Cancel", style: "cancel" },
              // The password prompt below IS the real confirmation.
              { text: "Continue to password", style: "destructive", onPress: () => setPending({ kind: "delete" }) },
            ]),
        },
      ],
    );
  };

  return (
    <View style={styles.container}>
      {/* Crisis help: one tap from here, works offline (see CrisisScreen). */}
      <TouchableOpacity style={[styles.button, styles.helpButton]} onPress={() => navigation.navigate("Crisis")}>
        <Text style={[styles.buttonText, styles.helpText]}>Need help now? Crisis resources</Text>
      </TouchableOpacity>
      <Text style={styles.label}>Server</Text>
      <TextInput style={styles.input} value={url} onChangeText={setUrl} autoCapitalize="none" placeholder="https://your-server:8000" placeholderTextColor="#5c6370" />
      <TouchableOpacity style={styles.button} onPress={saveUrl} disabled={busy}>
        <Text style={styles.buttonText}>Save server URL</Text>
      </TouchableOpacity>
      {llmAvailable && (
        <>
          <Text style={styles.label}>Third-party AI analysis</Text>
          <View style={styles.row}>
            <Text style={styles.rowText}>
              Allow sending your (decrypted) entries to an external AI service for pattern analysis.
              Off by default; needs your password to change.
            </Text>
            <Switch
              value={llmEnabled}
              disabled={busy}
              onValueChange={(enabled) => setPending({ kind: "llm", enabled })}
              trackColor={{ true: "#4f7cff", false: "#1a1e26" }}
            />
          </View>
        </>
      )}
      {pending && (
        <View style={styles.reauthCard}>
          <Text style={styles.reauthTitle}>
            {pending.kind === "delete"
              ? "Enter your password to delete everything"
              : `Enter your password to ${pending.enabled ? "enable" : "disable"} third-party AI analysis`}
          </Text>
          <TextInput
            style={styles.input}
            placeholder="password"
            placeholderTextColor="#5c6370"
            secureTextEntry
            value={password}
            onChangeText={setPassword}
          />
          <TouchableOpacity
            style={[styles.button, pending.kind === "delete" ? styles.danger : undefined]}
            onPress={confirmWithPassword}
            disabled={busy || !password}
          >
            <Text style={styles.buttonText}>{busy ? "Verifying…" : "Confirm with password"}</Text>
          </TouchableOpacity>
          <TouchableOpacity style={styles.ghost} disabled={busy} onPress={() => { setPending(null); setPassword(""); }}>
            <Text style={styles.ghostText}>Cancel</Text>
          </TouchableOpacity>
        </View>
      )}
      <TouchableOpacity style={styles.button} onPress={exportData} disabled={busy}>
        <Text style={styles.buttonText}>Export my data (encrypted)</Text>
      </TouchableOpacity>
      <TouchableOpacity style={[styles.button, styles.danger]} onPress={deleteEverything} disabled={busy}>
        <Text style={styles.buttonText}>Delete my account and data</Text>
      </TouchableOpacity>
      <TouchableOpacity style={styles.ghost} onPress={async () => { vault.lock(); await signOut(); navigation.popToTop(); }}>
        <Text style={styles.ghostText}>Sign out</Text>
      </TouchableOpacity>
      <Text style={styles.footnote}>
        Entries are encrypted on your device before they reach the server. Pattern analysis runs on
        the server in a single-use session — it is the one moment your data key travels there.
        No advice, no diagnosis, ever.
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f1115", padding: 24, gap: 14 },
  label: { color: "#8a91a3", fontSize: 12, fontWeight: "700", letterSpacing: 1, marginTop: 8 },
  input: { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 15 },
  button: { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" },
  helpButton: { backgroundColor: "#242a38" },
  helpText: { color: "#7f9bff" },
  danger: { backgroundColor: "#c0392b" },
  ghost: { padding: 12, alignItems: "center" },
  ghostText: { color: "#8a91a3", fontSize: 14 },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  row: { flexDirection: "row", alignItems: "center", gap: 12, backgroundColor: "#1a1e26", borderRadius: 10, padding: 14 },
  rowText: { color: "#b6bdc9", fontSize: 13, flex: 1, lineHeight: 18 },
  reauthCard: { backgroundColor: "#141821", borderRadius: 12, padding: 16, gap: 12 },
  reauthTitle: { color: "#e8eaf0", fontSize: 15, fontWeight: "600", lineHeight: 20 },
  footnote: { color: "#5c6370", fontSize: 12, textAlign: "center", marginTop: 16, lineHeight: 18 },
});
