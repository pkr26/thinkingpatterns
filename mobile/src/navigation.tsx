import React, { useRef, useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { useSession } from "./store";
import { useTheme } from "./theme";
import { LoginScreen } from "./screens/LoginScreen";
import { UnlockScreen } from "./screens/UnlockScreen";
import { OnboardingScreen } from "./screens/OnboardingScreen";
import { EntryScreen } from "./screens/EntryScreen";
import { HistoryScreen } from "./screens/HistoryScreen";
import { InsightsScreen } from "./screens/InsightsScreen";
import { QuestionScreen } from "./screens/QuestionScreen";
import { SettingsScreen } from "./screens/SettingsScreen";
import { TherapistShareScreen } from "./screens/TherapistShareScreen";
import { MeasuresScreen } from "./screens/MeasuresScreen";
import { PrivacyScreen } from "./screens/PrivacyScreen";
import { CrisisScreen } from "./screens/CrisisScreen";
import { takePendingOnboarding, hasSeenOnboarding, onboardingSeenCached } from "./onboarding";
import { api } from "./api/client";
import { MainShell, NavDestination } from "./components/BottomNav";

/** Wrap a main screen with the persistent bottom navigation (2026-09-17):
 *  reaching History after typing a long entry must not require scrolling
 *  past the text. EntryScreen hosts its own shell (keyboard behavior). */
function withShell(current: NavDestination) {
  // ComponentType<any>: the wrapped screens declare navigation as required
  // (they are only ever mounted by this navigator, which always provides it).
  return (Screen: React.ComponentType<any>) => {
    function Wrapped(props: { navigation?: any }): React.JSX.Element {
      const navigation = props.navigation as { navigate: (screen: string) => void } | undefined;
      return (
        <MainShell current={current} navigation={navigation}>
          <Screen navigation={navigation} />
        </MainShell>
      );
    }
    Wrapped.displayName = `MainShell(${current})`;
    return Wrapped;
  };
}

export type RootStackParamList = {
  Booting: undefined; // transient splash while a saved session resolves
  Login: undefined;
  Unlock: undefined;
  Onboarding: undefined;
  Entry: undefined;
  History: undefined;
  Insights: undefined;
  Question: undefined;
  Settings: undefined;
  TherapistShare: undefined;
  Measures: undefined;
  Privacy: undefined;
  Crisis: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

// Wrapped ONCE at module scope: a fresh component identity per render would
// remount the screen (destroying its local state — e.g. History edit drafts)
// on every AppNavigator re-render (session/active-days context changes).
const HistoryWithShell = withShell("History")(HistoryScreen);
const InsightsWithShell = withShell("Insights")(InsightsScreen);
const QuestionWithShell = withShell("Question")(QuestionScreen);
const SettingsWithShell = withShell("Settings")(SettingsScreen);

/** Branded boot splash (replacing the bare spinner): app name + the calm
 *  tagline while the saved session resolves from disk. */
function BootSplash(): React.JSX.Element {
  const t = useTheme();
  return (
    <View style={[styles.splash, { backgroundColor: t.colors.bg }]}>
      <Text style={[styles.brand, { color: t.colors.text }]} maxFontSizeMultiplier={1.6}>
        MindPattern
      </Text>
      <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
        Your patterns, from your words. Encrypted on this device.
      </Text>
      <ActivityIndicator color={t.colors.primaryBright} size="large" />
    </View>
  );
}

export function AppNavigator(): React.JSX.Element {
  // Tri-state: while "loading" a saved session may still be resolving from
  // disk — rendering Login in that window let a second account sign in over
  // a live one without any wipe running (the audit's login-flash race).
  const { authStatus, unlocked } = useSession();
  // A just-registered account routes through onboarding ONCE, before the
  // journal. The pending flag is consumed here at the moment the main flow
  // is entered, so a later plain login or unlock in the same session never
  // sees it (src/onboarding.ts). Setting state during render is the
  // documented React pattern for deriving state from a prop transition.
  const inMain = authStatus === "loggedIn" && unlocked;
  // Starts false deliberately: mounting DIRECTLY into the main flow counts
  // as a transition (the first render then consumes the pending flag).
  const wasInMain = useRef(false);
  // Stryker disable next-line BooleanLiteral: showOnboarding is read only inside the main branch, and the first main render always flips wasInMain (it starts false) and overwrites the state — the initial value never reaches the tree
  const [showOnboarding, setShowOnboarding] = useState(false);
  // M-18 (2026-09-20 audit): backgrounding mid-onboarding locks the vault
  // (inMain flips false) and CONSUMES the one-shot pending flag — the old
  // gate re-entered main on the journal with the privacy/13+ panels never
  // shown or completed. The gate is therefore re-derived on EVERY entry
  // into the main flow from the PERSISTED per-account flag too: onboarding
  // shows until recordOnboardingSeen lands, however the user left it.
  // accountRef holds the signed-in account id once resolved (render-time
  // reads must be synchronous); onboardingResolved gates the first main
  // paint until that resolution is in (a BootSplash beat, not an Entry
  // flash that would have to be walked back).
  const accountRef = useRef<string | null>(null);
  const [onboardingResolved, setOnboardingResolved] = useState(false);
  if (inMain !== wasInMain.current) {
    wasInMain.current = inMain;
    // Stryker disable next-line BooleanLiteral: leaving main sets wasInMain false, so re-entering main always fires the transition again and overwrites this value before it can render
    setShowOnboarding(
      inMain
        ? takePendingOnboarding() || (accountRef.current !== null && onboardingSeenCached(accountRef.current) === false)
        : false,
    );
  }

  // Prime the persisted-flag mirror for the signed-in account (and record
  // which account the gate decides for). Fail toward "seen": with a broken
  // store, looping the three panels on every entry would trap the user,
  // while a failed recordOnboardingSeen only shows them once more.
  React.useEffect(() => {
    if (authStatus !== "loggedIn") {
      accountRef.current = null;
      setOnboardingResolved(false);
      return;
    }
    let cancelled = false;
    void (async () => {
      const userId = await api.getUserId().catch(() => null);
      if (cancelled) return;
      accountRef.current = userId;
      if (!userId) {
        setOnboardingResolved(true);
        return;
      }
      await hasSeenOnboarding(userId).catch(() => {});
      if (cancelled) return;
      setOnboardingResolved(true);
      // Resolution landing while the main flow is already past its
      // transition (rare — the unlock screen usually covers this window):
      // surface onboarding as the initial route now, not never.
      if (onboardingSeenCached(userId) === false) setShowOnboarding(true);
    })();
    return () => {
      cancelled = true;
    };
  }, [authStatus]);

  return (
    <Stack.Navigator>
      {authStatus === "loading" ? (
        <>
          <Stack.Screen name="Booting" component={BootSplash} options={{ headerShown: false }} />
          {/* Crisis help stays reachable even while the saved session is
              still resolving — "always one or two interactions away". */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      ) : authStatus === "loggedOut" ? (
        <>
          <Stack.Screen name="Login" component={LoginScreen} options={{ headerShown: false }} />
          {/* Crisis help must be reachable BEFORE any sign-in: it is offline
              static content and never needs the vault or the network. */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      ) : !unlocked ? (
        // Logged in (token on disk) but the memory-only key vault is locked:
        // a cold restart must land here, not on a screen that throws.
        <>
          <Stack.Screen name="Unlock" component={UnlockScreen} options={{ headerShown: false }} />
          {/* Vault-locked users are at their most vulnerable moment — the
              crisis screen must stay one tap away without unlocking. */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      ) : !onboardingResolved && !showOnboarding ? (
        // M-18: the persisted onboarding flag has not been resolved for the
        // signed-in account yet. Holding the boot splash here (instead of
        // rendering Entry first) lets onboarding, when due, be the FIRST
        // screen of the main flow — no journal flash before the panels.
        <>
          <Stack.Screen name="Booting" component={BootSplash} options={{ headerShown: false }} />
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      ) : (
        <>
          {/* First run after registration only: three calm panels, then the
              journal. Declared first so it is the initial route when shown. */}
          {showOnboarding && (
            <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ headerShown: false }} />
          )}
          <Stack.Screen name="Entry" component={EntryScreen} options={{ title: "Today" }} />
          <Stack.Screen name="History" component={HistoryWithShell} options={{ title: "History" }} />
          <Stack.Screen name="Insights" component={InsightsWithShell} options={{ title: "Patterns" }} />
          <Stack.Screen name="Question" component={QuestionWithShell} options={{ title: "One question" }} />
          <Stack.Screen name="Settings" component={SettingsWithShell} options={{ title: "Settings" }} />
          <Stack.Screen name="TherapistShare" component={TherapistShareScreen} options={{ title: "My therapist" }} />
          <Stack.Screen name="Measures" component={MeasuresScreen} options={{ title: "Wellbeing measures" }} />
          {/* The privacy policy is static, offline content (like Crisis). */}
          <Stack.Screen name="Privacy" component={PrivacyScreen} options={{ title: "Privacy" }} />
          {/* Crisis help: one navigation hop from every screen (offline,
              static content — see CrisisScreen). */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      )}
    </Stack.Navigator>
  );
}

const styles = StyleSheet.create({
  splash: { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 },
  brand: { fontSize: 28, fontWeight: "700" },
});
