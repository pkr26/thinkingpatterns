/**
 * Share with my therapist — the patient side of the zero-knowledge sharing
 * flow (see backend/app/api/consents.py for the server contract).
 *
 * Flow: the therapist's portal shows a short-lived pairing code; the
 * patient types it here. Lookup answers with the therapist's NAME and
 * public key — nothing is shared yet. Only after the disclosure below and
 * a password re-authentication does the app wrap its data key to that
 * therapist's public key (crypto/sharing.ts) and grant. The data key
 * leaves the device exactly once, inside that wrap.
 *
 * Revoking is symmetric: password re-auth, then the server drops the
 * wrapped key — future access dies instantly. The disclosure is honest
 * that already-read data cannot be unread.
 */
import React, { useCallback, useEffect, useState } from "react";
import { Alert, ScrollView, StyleSheet, Text, TextInput, View } from "react-native";
import { api, type ListedConsent, type PairingLookup } from "../api/client";
import { vault } from "../vault";
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../reauth";
import { therapistKeyFingerprint, wrapDataKeyForTherapist } from "../crypto/sharing";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { calmFallbackCopy } from "../components/errors";

type PendingAction =
  | { kind: "grant"; code: string; lookup: PairingLookup }
  | { kind: "revoke"; consentId: string }
  | null;

const dayOf = (iso: string): string => iso.slice(0, 10);

export function TherapistShareScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const [consents, setConsents] = useState<ListedConsent[]>([]);
  const [code, setCode] = useState("");
  const [lookup, setLookup] = useState<PairingLookup | null>(null);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  /** Unknown is rendered as unavailable until the server explicitly opts in;
   * that prevents an old/misconfigured server from presenting a pairing flow
   * which will only fail later with a confusing 404/403. */
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);

  const refresh = useCallback(() => {
    api.meta()
      .then((meta) => {
        const enabled = meta?.sharing_available === true;
        setSharingAvailable(enabled);
        if (enabled) api.listConsents().then(setConsents).catch(() => setConsents([]));
        else setConsents([]);
      })
      .catch(() => {
        setSharingAvailable(false);
        setConsents([]);
      });
  }, []);
  useEffect(refresh, [refresh]);

  const findTherapist = async () => {
    if (busy || sharingAvailable !== true || !code.trim()) return;
    setBusy(true);
    try {
      const found = await api.pairingLookup(code.trim());
      setLookup(found);
    } catch (err) {
      if (isSessionExpiredError(err)) {
        Alert.alert("Session expired", "Please unlock again.");
      } else {
        Alert.alert(
          "Code not found",
          "Check the code with your therapist — it expires 15 minutes after they generate it.",
        );
      }
    } finally {
      setBusy(false);
    }
  };

  const confirmGrant = () => {
    if (!lookup) return;
    Alert.alert(
      `Share with ${lookup.display_name}?`,
      "They will be able to read every journal entry and every pattern computed from them, " +
        "from their therapist portal. They cannot change or delete anything — only read, and " +
        "write their own private notes.\n\n" +
        "You can stop sharing at any time; that ends their access immediately, but it cannot " +
        "unread what they have already seen. You will be asked for your password.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Continue to password",
          style: "destructive",
          onPress: () => setPending({ kind: "grant", code: code.trim(), lookup }),
        },
      ],
    );
  };

  const askRevoke = (consent: ListedConsent) => {
    if (busy) return;
    Alert.alert(
      `Stop sharing with ${consent.display_name}?`,
      "Their access ends immediately. They keep anything they have already read. " +
        "You will be asked for your password.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Stop sharing",
          style: "destructive",
          onPress: () => setPending({ kind: "revoke", consentId: consent.id }),
        },
      ],
    );
  };

  /** Both flows land here: the action only runs after the typed password
   *  re-derives the vault's own auth key (the reauth.ts contract). */
  const confirmWithPassword = async () => {
    if (!pending || busy || !password) return;
    setBusy(true);
    const done = () => { setBusy(false); setPending(null); setPassword(""); setLookup(null); setCode(""); };
    const retry = () => { setBusy(false); setPassword(""); };
    try {
      const reauth = await verifyPasswordForVault(password);
      if (!reauth.ok) {
        const messages = {
          locked: "The vault is locked — unlock again first.",
          "no-account": "No saved account on this device — sign in again.",
          "wrong-password": "Wrong password.",
          offline: "Cannot verify your password offline right now — try again when online.",
        } as const;
        Alert.alert("Could not verify", messages[reauth.reason]);
        retry();
        return;
      }
      if (pending.kind === "grant") {
        const userId = await api.getUserId();
        if (!userId) throw new Error("no saved account on this device");
        // The data key leaves the device exactly once: inside this wrap.
        const wrap = wrapDataKeyForTherapist(
          vault.get().dataKey,
          pending.lookup.wrap_pub_key,
          userId,
          pending.lookup.therapist_id,
        );
        await api.grantConsent(pending.code, wrap.ephemeralPubB64, wrap.wrappedKeyB64, reauth.verifierB64);
        Alert.alert(
          "Sharing started",
          `${pending.lookup.display_name} can now read your entries and patterns from their portal.`,
        );
      } else {
        await api.revokeConsent(pending.consentId, reauth.verifierB64);
        Alert.alert("Sharing stopped", "Their access has ended.");
      }
      refresh();
      done();
    } catch (err) {
      if (isVerificationFailedError(err)) {
        Alert.alert("That password didn't match", "Check it and try again — nothing was changed.");
        retry();
        return;
      }
      if (isSessionExpiredError(err)) {
        Alert.alert("Session expired", "Please unlock again.");
      } else {
        Alert.alert("Could not complete", calmFallbackCopy(err, "Something went wrong — try again."));
      }
      done();
    }
  };

  const themed = {
    label: { color: t.colors.muted, fontSize: 12, fontWeight: "700" as const, letterSpacing: 1, marginTop: 8 },
    input: {
      backgroundColor: t.colors.card,
      color: t.colors.text,
      borderRadius: t.radius.md,
      padding: 14,
      fontSize: 15,
    },
    rowText: { color: t.colors.body, fontSize: 13, flex: 1, lineHeight: 18 },
    footnote: { color: t.colors.muted, fontSize: 12, lineHeight: 18 },
  };

  return (
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxl, gap: 14 }]}
      contentContainerStyle={{ paddingBottom: t.spacing.xxxl }}
    >
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />

      {sharingAvailable !== true && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>Therapist sharing unavailable</Text>
          <Text style={themed.footnote}>
            This server has not enabled verified clinician sharing. No pairing code or journal data will be sent.
          </Text>
          <GhostButton label="Back" center={false} onPress={() => navigation.goBack?.()} />
        </View>
      )}

      {sharingAvailable === true && <Text style={themed.label}>Sharing now</Text>}
      {sharingAvailable === true && consents.length === 0 && (
        <Text style={themed.footnote}>
          You are not sharing with anyone. Your entries stay visible only to you.
        </Text>
      )}
      {sharingAvailable === true && consents.map((consent) => (
        <View
          key={consent.id}
          style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}
        >
          <Text style={themed.rowText}>
            {consent.display_name}{"\n"}
            <Text style={themed.footnote}>
              {consent.status === "active"
                ? `Sharing since ${dayOf(consent.granted_at)}`
                : `Stopped ${consent.revoked_at ? dayOf(consent.revoked_at) : ""}`}
            </Text>
          </Text>
          {consent.status === "active" && (
            <GhostButton
              label="Stop sharing"
              center={false}
              disabled={busy}
              onPress={() => askRevoke(consent)}
            />
          )}
        </View>
      ))}

      {sharingAvailable === true && !lookup && (
        <>
          <Text style={themed.label}>Add your therapist</Text>
          <Text style={themed.footnote}>
            Ask your therapist for a pairing code from their portal, then enter it here. Codes
            expire after 15 minutes.
          </Text>
          <TextInput
            style={themed.input}
            value={code}
            onChangeText={setCode}
            autoCapitalize="characters"
            placeholder="e.g. 7X2KQM4N"
            placeholderTextColor={t.colors.placeholder}
            accessibilityLabel="Therapist pairing code"
          />
          <PrimaryButton
            label={busy ? "Looking up…" : "Find my therapist"}
            onPress={findTherapist}
            disabled={busy || !code.trim()}
          />
        </>
      )}

      {sharingAvailable === true && lookup && !pending && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={[styles.cardTitle, { color: t.colors.text }]}>{lookup.display_name}</Text>
          <Text style={themed.footnote}>
            {`Key fingerprint: ${therapistKeyFingerprint(lookup.wrap_pub_key)}\n`}
            Read it back to your therapist and check it matches the one their portal
            shows — a mismatch means the key was substituted in transit.
          </Text>
          <Text style={themed.footnote}>
            Sharing lets them read every entry and pattern (never change anything), and write their
            own private notes. You can stop at any time; what they already read cannot be unread.
          </Text>
          <PrimaryButton
            label={`Share with ${lookup.display_name}`}
            onPress={confirmGrant}
            disabled={busy}
          />
          <GhostButton
            label="Cancel"
            disabled={busy}
            onPress={() => { setLookup(null); setCode(""); }}
          />
        </View>
      )}

      {sharingAvailable === true && pending && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {pending.kind === "grant"
              ? `Enter your password to share with ${pending.lookup.display_name}`
              : "Enter your password to stop sharing"}
          </Text>
          <TextInput
            style={themed.input}
            placeholder="password"
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={password}
            onChangeText={setPassword}
            accessibilityLabel="Password confirmation"
            textContentType="password"
          />
          <PrimaryButton
            label={busy ? "Verifying…" : "Confirm with password"}
            onPress={confirmWithPassword}
            disabled={!password}
            danger={pending.kind === "revoke"}
            accessibilityLabel="Confirm with password"
          />
          <GhostButton
            label="Cancel"
            disabled={busy}
            onPress={() => { setPending(null); setPassword(""); }}
          />
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  card: { padding: 16, gap: 8 },
  cardTitle: { fontSize: 15, fontWeight: "600" },
  reauthCard: { padding: 16, gap: 12 },
  reauthTitle: { fontSize: 15, fontWeight: "600", lineHeight: 20 },
});
