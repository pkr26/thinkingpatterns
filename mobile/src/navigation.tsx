import React, { useRef, useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { useSession } from "./store";
import { useTheme } from "./theme";
import { LoginScreen } from "./screens/LoginScreen";
import { RecoveryScreen } from "./screens/RecoveryScreen";
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
import { SafetyPlanScreen } from "./screens/SafetyPlanScreen";
import { takePendingOnboarding, hasSeenOnboarding, onboardingSeenCached } from "./onboarding";
import { takePendingNotificationRoute, subscribeNotificationRoutes } from "./notificationRoute";
import { api } from "./api/client";
import { t as tr } from "./strings";
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
  Recovery: undefined;
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
  SafetyPlan: undefined;
};

export const navigationRef = {
  current: null as any,
  isReady: (): boolean => navigationRef.current?.isReady?.() === true,
  navigate: (screen: string): void => { navigationRef.current?.navigate(screen); },
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
        Fathom
      </Text>
      <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
        {/* 2026-09-26 audit M-M4: the tagline was hardcoded English while
            the identical copy already lives in the catalog as
            login.subtitle — resolve it through tr() like every other
            user-visible string. */}
        {tr("login.subtitle")}
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
  // The measure nudge's tapped destination (2026-09-27), consumed ONCE at
  // main-flow entry — the takePendingOnboarding idiom. When a nudge tap
  // queued "Measures", the Measures screen is declared FIRST in the main
  // branch so it is the INITIAL screen (deep links land on their target);
  // a normal cold start queues nothing and Entry leads, as always.
  const [routeVersion, setRouteVersion] = useState(0);
  React.useEffect(() => subscribeNotificationRoutes(() => setRouteVersion(v => v + 1)), []);
  const [notificationScreen, setNotificationScreen] = useState<string | null>(null);
  const measuresLeads = notificationScreen === "Measures";
  const measuresScreen = (
    <Stack.Screen name="Measures" component={MeasuresScreen} options={{ title: tr("nav.measures") }} />
  );
  // M-18 (2026-09-20 audit): backgrounding mid-onboarding locks the vault
  // (inMain flips false) and CONSUMES the one-shot pending flag — the old
  // gate re-entered main on the journal with the privacy/18+ panels never
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
    setNotificationScreen(inMain ? takePendingNotificationRoute() : null);
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

  React.useEffect(() => {
    if (!inMain || showOnboarding || !onboardingResolved) return;
    if (!navigationRef.isReady()) return;
    const screen = takePendingNotificationRoute();
    if (screen) {
      setNotificationScreen(screen);
      // Navigator itself is already mounted for a foreground/late-cold tap.
      navigationRef.navigate(screen);
    }
  }, [routeVersion, inMain, showOnboarding, onboardingResolved]);
  return (
    <Stack.Navigator>
      {authStatus === "loading" ? (
        <>
          <Stack.Screen name="Booting" component={BootSplash} options={{ headerShown: false }} />
          {/* Crisis help stays reachable even while the saved session is
              still resolving — "always one or two interactions away". */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: tr("nav.getHelp") }} />
        </>
      ) : authStatus === "loggedOut" ? (
        <>
          <Stack.Screen name="Login" component={LoginScreen} options={{ headerShown: false }} />
          <Stack.Screen name="Recovery" component={RecoveryScreen} options={{ headerShown: false }} />
          {/* Crisis help must be reachable BEFORE any sign-in: it is offline
              static content and never needs the vault or the network. */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: tr("nav.getHelp") }} />
        </>
      ) : !unlocked ? (
        // Logged in (token on disk) but the memory-only key vault is locked:
        // a cold restart must land here, not on a screen that throws.
        <>
          <Stack.Screen name="Unlock" component={UnlockScreen} options={{ headerShown: false }} />
          {/* Vault-locked users are at their most vulnerable moment — the
              crisis screen must stay one tap away without unlocking. */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: tr("nav.getHelp") }} />
        </>
      ) : !onboardingResolved && !showOnboarding ? (
        // M-18: the persisted onboarding flag has not been resolved for the
        // signed-in account yet. Holding the boot splash here (instead of
        // rendering Entry first) lets onboarding, when due, be the FIRST
        // screen of the main flow — no journal flash before the panels.
        <>
          <Stack.Screen name="Booting" component={BootSplash} options={{ headerShown: false }} />
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: tr("nav.getHelp") }} />
        </>
      ) : (
        <>
          {/* First run after registration only: three calm panels, then the
              journal. Declared first so it is the initial route when shown. */}
          {showOnboarding && (
            <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ headerShown: false }} />
          )}
          {/* 2026-09-26 audit M-M4: every screen title resolves through tr()
              at render time (the locale is startup-fixed, so per-render
              lookup is stable) — they were hardcoded English while nav.*
              keys existed in both catalogs. */}
          {/* A tapped measure nudge (2026-09-27): Measures is the initial
              screen of this main-flow entry — declared before Entry, the
              same initial-route idiom as onboarding above. */}
          {measuresLeads && measuresScreen}
          <Stack.Screen name="Entry" component={EntryScreen} options={{ title: tr("nav.today") }} />
          <Stack.Screen name="History" component={HistoryWithShell} options={{ title: tr("nav.history") }} />
          <Stack.Screen name="Insights" component={InsightsWithShell} options={{ title: tr("nav.patterns") }} />
          <Stack.Screen name="Question" component={QuestionWithShell} options={{ title: tr("nav.questionTitle") }} />
          <Stack.Screen name="Settings" component={SettingsWithShell} options={{ title: tr("nav.settings") }} />
          <Stack.Screen name="TherapistShare" component={TherapistShareScreen} options={{ title: tr("nav.therapist") }} />
          {!measuresLeads && measuresScreen}
          {/* The local safety plan (2026-09-27): a main-flow screen — it
              reads and writes under the vault's data key, so it exists only
              where the vault is unlocked. */}
          <Stack.Screen name="SafetyPlan" component={SafetyPlanScreen} options={{ title: tr("safetyplan.navTitle") }} />
          {/* The privacy policy is static, offline content (like Crisis). */}
          <Stack.Screen name="Privacy" component={PrivacyScreen} options={{ title: tr("nav.privacy") }} />
          {/* Crisis help: one navigation hop from every screen (offline,
              static content — see CrisisScreen). */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: tr("nav.getHelp") }} />
        </>
      )}
    </Stack.Navigator>
  );
}

const styles = StyleSheet.create({
  splash: { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 },
  brand: { fontSize: 28, fontWeight: "700" },
});
