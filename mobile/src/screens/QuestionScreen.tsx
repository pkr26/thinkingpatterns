/**
 * Today's single reflective question.
 *
 * Order of operations (fixed after the audit): the phase is checked FIRST —
 * GET /api/insights needs no key. A processing session (which sends the
 * data key over TLS to the server for the mini-brain) is only ever opened
 * when the account is in the insight phase AND the user has tapped to do
 * exactly that. Errors are surfaced, never swallowed: the old catch-all
 * silently fell through to the key-shipping branch on ANY failure.
 */
import React, { useState } from "react";
import { ActivityIndicator, Alert, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { api, ApiError } from "../api/client";
import { decryptQuestion } from "../crypto/MindPatternCrypto";
import { vault } from "../vault";
import { useSession } from "../store";

export function QuestionScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const { touchActivity } = useSession();
  const [question, setQuestion] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decryptToday = async () => {
    const userId = await api.getUserId();
    if (!userId) throw new Error("account id missing — sign in again");
    const direct = await api.questionToday();
    // The blob's AAD is bound to the server's calendar date — always
    // decrypt with the for_date the server reported, never a locally
    // computed "today" (timezones would break authentication).
    return decryptQuestion(vault.get(), userId, direct.for_date, direct.blob);
  };

  const load = async () => {
    setBusy(true);
    setError(null);
    try {
      // 1) Is the account even in the insight phase? No key required.
      const summary = await api.insights();
      if (summary.phase !== "insight") {
        setError(`Patterns are not unlocked yet — one question per day starts after day ${summary.days_remaining + summary.active_days}.`);
        return;
      }
      // 2) A question may already exist for today — no key required either.
      try {
        const payload = await decryptToday();
        setQuestion(payload.question);
        return;
      } catch (err) {
        // 404 = none stored yet (expected, continue to recompute). Anything
        // else is a real failure and must NOT silently fall through to
        // opening a processing session.
        if (!(err instanceof ApiError && err.status === 404)) throw err;
      }
      // 3) Insight phase, no question yet: this step sends the data key in
      // a single-use processing session. The button press IS the consent.
      // The vault must hold THIS account's keys — a session/vault desync
      // must never ship one account's key into another's session.
      const sessionUserId = await api.getUserId();
      if (!sessionUserId || vault.ownerUserId() !== sessionUserId) {
        throw new Error("session and unlocked keys do not match — sign in again");
      }
      const session = await api.openProcessingSession(vault.get().dataKey.toString("base64"));
      const result = await api.recompute(session.session_token);
      if (!result.question_stored) {
        setError("No recurring pattern has enough evidence yet — keep writing.");
        return;
      }
      const payload = await decryptToday();
      setQuestion(payload.question);
    } catch (err) {
      const message = err instanceof ApiError && err.status === 401
        ? "Session expired — unlock again."
        : err instanceof Error ? err.message : "could not load today's question";
      setError(message);
      if (!(err instanceof ApiError)) {
        // Local crypto failures are unexpected enough to be worth a dialog.
        Alert.alert("Could not load question", message);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    // Any touch on this screen is real interaction: restart the inactivity
    // countdown so the auto-lock only fires on a genuinely idle session.
    <View style={styles.container} onTouchStart={touchActivity}>
      {busy && <ActivityIndicator color="#4f7cff" size="large" />}
      {error && <Text style={styles.error}>{error}</Text>}
      {question && (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Today</Text>
          <Text style={styles.question}>{question}</Text>
          <Text style={styles.footnote}>One question a day. No advice — just something to sit with.</Text>
        </View>
      )}
      <TouchableOpacity style={styles.button} onPress={load} disabled={busy}>
        <Text style={styles.buttonText}>{question ? "Refresh" : "Show today's question"}</Text>
      </TouchableOpacity>
      <TouchableOpacity onPress={() => navigation.navigate("Crisis")} accessibilityRole="button">
        <Text style={styles.helpLink}>Need help now? Crisis resources</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f1115", padding: 24, justifyContent: "center", gap: 18 },
  card: { backgroundColor: "#1a1e26", borderRadius: 14, padding: 22, gap: 12 },
  cardTitle: { color: "#7f9bff", fontSize: 12, fontWeight: "700", letterSpacing: 1.5 },
  question: { color: "#e8eaf0", fontSize: 22, fontWeight: "600", lineHeight: 30 },
  footnote: { color: "#5c6370", fontSize: 12 },
  button: { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  error: { color: "#ff6b6b", fontSize: 13, textAlign: "center" },
  helpLink: { color: "#7f9bff", fontSize: 13, fontWeight: "600", textAlign: "center" },
});
