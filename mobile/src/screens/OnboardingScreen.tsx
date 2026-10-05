/**
 * First-run onboarding — three short, calm panels shown ONCE after a
 * registration (state in src/onboarding.ts): what Fathom is, how the
 * encryption protects the journal (with the one honest exception), and the
 * no-recovery warning with the 18+ line (2026-09-27: the age floor moved
 * from 13+ to 18+ with the registration age gate — audit 2026-09-28 fixed
 * this stale comment). No verification theater: the acknowledgment is a
 * single button.
 *
 * The privacy policy is one tap from the encryption panel; crisis help is
 * one tap from every panel — a brand-new account is not a reason to be
 * further from support.
 */
import React, { useEffect, useRef, useState } from "react";
import { ScrollView, StyleSheet, Switch, Text, View } from "react-native";
import { api } from "../api/client";
import { useSession } from "../store";
import { useTheme } from "../theme";
import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { hasSeenOnboarding, loadOnboardingPanel, recordOnboardingSeen, saveOnboardingPanel } from "../onboarding";
import { setReminderEnabled } from "../reminders";
import { useReminderPreferenceIntent } from "../reminderPreferences";
import { syncReminderSchedule } from "../reminderSync";
import { t as tr } from "../strings";

interface Panel {
  title: string;
  body: string;
}

// Per render (2026-09-29 deep audit, P2): the in-app language override
// changes currentLocale at runtime; a module-load table froze the
// import-time locale (the 2026-09-26 i18n guard's warning, now resolved).
function panels(): readonly Panel[] {
  return [
    {
      title: tr("onboarding.panel1Title"),
      body: tr("onboarding.panel1Body"),
    },
    {
      title: tr("onboarding.panel2Title"),
      body: tr("onboarding.panel2Body"),
    },
    {
      title: tr("onboarding.panel3Title"),
      body: tr("onboarding.panel3Body"),
    },
  ];
}

export function OnboardingScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const beginReminderIntent = useReminderPreferenceIntent();
  const [index, setIndex] = useState(0);
  const [busy, setBusy] = useState(false);
  // The reminder opt-in (2026-09-19): off by default, one tap to say yes,
  // changeable later in Settings. Calm copy — an invitation, never a debt.
  const [remind, setRemind] = useState(false);
  const [owner, setOwner] = useState<string | null>(null);
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
        setOwner(userId);
        // Stryker disable next-line ArrowFunction: () => false vs () => undefined are indistinguishable — `seen` is only truthiness-tested in `!cancelled && seen`
        const seen = await hasSeenOnboarding(userId).catch(() => false);
        if (!cancelled && seen) navigation.replace("Entry");
        const restored = await loadOnboardingPanel(panels().length, userId).catch(() => 0);
        if (!cancelled && restored > 0) setIndex(restored);
      })
      .catch(() => {});
    // E-10 (2026-09-21): M-18's re-entry restored the screen but not the
    // dismissed-panel position — resume where the user left off instead
    // of restarting at panel 1.
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

  const last = index === panels().length - 1;
  const panel = panels()[index]!;

  /** Persist the reminder opt-in per account. The onboarding flow runs
   *  right after registration, so the account exists — but if the id read
   *  fails, skip silently: onboarding must never block or nag. */
  const toggleRemind = (on: boolean) => {
    touchActivity();
    const intent = beginReminderIntent("daily-enabled", owner ?? undefined);
    if (!intent) return;
    setRemind(on);
    api
      .getUserId()
      .then(async (userId) => {
        if (!intent.current() || userId !== intent.owner) return;
        await setReminderEnabled(userId, on);
        if (!intent.current()) return;
        await syncReminderSchedule(userId).catch(() => {});
      })
      .catch(() => {});
  };

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
        {tr("onboarding.stepOf", { current: index + 1, total: panels().length })}
      </Text>
      <Text style={[styles.title, { color: t.colors.text }]} maxFontSizeMultiplier={1.6}>
        {panel.title}
      </Text>
      <Text style={[styles.body, { color: t.colors.body }]}>{panel.body}</Text>
      {index === 0 && (
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
          <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, flex: 1, lineHeight: 19 }}>
            {tr("onboarding.remindQuestion")}
          </Text>
          <Switch
            value={remind}
            onValueChange={toggleRemind}
            accessibilityLabel={tr("settings.dailyReminderA11y")}
            accessibilityState={{ checked: remind }}
          />
        </View>
      )}
      {index === 1 && (
        <GhostButton label={tr("onboarding.readPrivacy")} onPress={() => navigation.navigate("Privacy")} />
      )}
      {last && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("onboarding.ageNotice")}
        </Text>
      )}
      <PrimaryButton
        label={last ? tr("onboarding.start") : tr("common.continue")}
        onPress={
          last
            ? () => void finish()
            : () => {
                touchActivity();
                // E-10 (2026-09-21): persist the position so a backgrounded
                // onboarding resumes here (see loadOnboardingPanel above).
                if (owner) void saveOnboardingPanel(index + 1, owner);
                setIndex(index + 1);
              }
        }
        busy={busy}
        accessibilityLabel={
          last
            ? tr("onboarding.start")
            : tr("onboarding.continueA11y", { next: index + 2, total: panels().length })
        }
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
