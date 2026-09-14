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
import { PrivacyScreen } from "./screens/PrivacyScreen";
import { CrisisScreen } from "./screens/CrisisScreen";
import { takePendingOnboarding } from "./onboarding";

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
  Privacy: undefined;
  Crisis: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

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
  const [showOnboarding, setShowOnboarding] = useState(false);
  if (inMain !== wasInMain.current) {
    wasInMain.current = inMain;
    setShowOnboarding(inMain ? takePendingOnboarding() : false);
  }
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
      ) : (
        <>
          {/* First run after registration only: three calm panels, then the
              journal. Declared first so it is the initial route when shown. */}
          {showOnboarding && (
            <Stack.Screen name="Onboarding" component={OnboardingScreen} options={{ headerShown: false }} />
          )}
          <Stack.Screen name="Entry" component={EntryScreen} options={{ title: "Today" }} />
          <Stack.Screen name="History" component={HistoryScreen} options={{ title: "History" }} />
          <Stack.Screen name="Insights" component={InsightsScreen} options={{ title: "Patterns" }} />
          <Stack.Screen name="Question" component={QuestionScreen} options={{ title: "One question" }} />
          <Stack.Screen name="Settings" component={SettingsScreen} options={{ title: "Settings" }} />
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
