/**
 * First-run onboarding — three short, calm panels shown ONCE after a
 * registration (state in src/onboarding.ts): what MindPattern is, how the
 * encryption protects the journal (with the one honest exception), and the
 * no-recovery warning with the 13+ line. No verification theater: the
 * acknowledgment is a single button.
 *
 * The privacy policy is one tap from the encryption panel; crisis help is
 * one tap from every panel — a brand-new account is not a reason to be
 * further from support.
 */
import React, { useEffect, useRef, useState } from "react";
import { ScrollView, StyleSheet, Text, View } from "react-native";
import { api } from "../api/client";
import { useSession } from "../store";
import { useTheme } from "../theme";
import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { hasSeenOnboarding, recordOnboardingSeen } from "../onboarding";

interface Panel {
  title: string;
  body: string;
}

const PANELS: readonly Panel[] = [
  {
    title: "Write each day",
    body: "After 30 days of writing, the app shows you patterns too slow to notice on your own — every one with the evidence behind it. Never advice, never a diagnosis.",
  },
  {
    title: "Your words stay yours",
    body: "Your password derives the encryption keys on this device, and everything you write is encrypted before it leaves — the server stores only ciphertext. The one exception: when you start a pattern analysis yourself, your key is used once — held in memory for up to 5 minutes, then destroyed. It is never stored.",
  },
  {
    title: "Keep your password safe",
    body: "There is no password reset — write your password down somewhere safe. If it is lost, no one, including us, can recover your journal.",
  },
];

export function OnboardingScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [index, setIndex] = useState(0);
  const [busy, setBusy] = useState(false);
  // Double-tap guard: two presses inside one frame both pass a state-only
  // check — the ref is synchronous (the Entry screen's savingRef pattern).
  const busyRef = useRef(false);

  useEffect(() => {
    // Landing here with the acknowledgment already recorded should be
    // impossible (the navigator routes here once) — if it happens, go
    // straight to the journal instead of lecturing twice.
    let cancelled = false;
    api
      .getUserId()
      .then(async (userId) => {
        if (!userId) return;
        // Stryker disable next-line ArrowFunction: () => false vs () => undefined are indistinguishable — `seen` is only truthiness-tested in `!cancelled && seen`
        const seen = await hasSeenOnboarding(userId).catch(() => false);
        if (!cancelled && seen) navigation.replace("Entry");
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
    }, // Stryker disable next-line ArrayDeclaration: navigation is identity-stable for a mounted screen; an extra effect run would only repeat the idempotent seen-check
     [navigation]);

  const finish = async () => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    // Stryker disable next-line ArrowFunction: () => null vs () => undefined are indistinguishable — `userId` is only falsiness-tested in `if (userId)`
    const userId = await api.getUserId().catch(() => null);
    if (userId) {
      // Losing this write just shows the panels once more — never block on it.
      await recordOnboardingSeen(userId).catch(() => {});
    }
    navigation.replace("Entry");
  };

  const last = index === PANELS.length - 1;
  const panel = PANELS[index]!;

  return (
    <ScrollView
      style={{ flex: 1, backgroundColor: t.colors.bg }}
      contentContainerStyle={{ flexGrow: 1, paddingBottom: t.spacing.xxxl }}
    >
      <View
        style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxl, gap: 18 }]}
        onTouchStart={touchActivity}
      >
      <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
        {index + 1} of {PANELS.length}
      </Text>
      <Text style={[styles.title, { color: t.colors.text }]} maxFontSizeMultiplier={1.6}>
        {panel.title}
      </Text>
      <Text style={[styles.body, { color: t.colors.body }]}>{panel.body}</Text>
      {index === 1 && (
        <GhostButton label="Read the privacy policy" onPress={() => navigation.navigate("Privacy")} />
      )}
      {last && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          MindPattern is for people 13 and older — by continuing you confirm that you are.
        </Text>
      )}
      <PrimaryButton
        label={last ? "I understand — start writing" : "Continue"}
        onPress={
          last
            ? () => void finish()
            : () => {
                touchActivity();
                setIndex(index + 1);
              }
        }
        busy={busy}
        accessibilityLabel={last ? "I understand — start writing" : `Continue to panel ${index + 2} of ${PANELS.length}`}
      />
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center" },
  title: { fontSize: 26, fontWeight: "700", lineHeight: 33 },
  body: { fontSize: 16, lineHeight: 24 },
});
