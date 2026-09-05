import React from "react";
import { ActivityIndicator, StyleSheet, View } from "react-native";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { useSession } from "./store";
import { LoginScreen } from "./screens/LoginScreen";
import { UnlockScreen } from "./screens/UnlockScreen";
import { EntryScreen } from "./screens/EntryScreen";
import { InsightsScreen } from "./screens/InsightsScreen";
import { QuestionScreen } from "./screens/QuestionScreen";
import { SettingsScreen } from "./screens/SettingsScreen";
import { CrisisScreen } from "./screens/CrisisScreen";

export type RootStackParamList = {
  Booting: undefined; // transient splash while a saved session resolves
  Login: undefined;
  Unlock: undefined;
  Entry: undefined;
  Insights: undefined;
  Question: undefined;
  Settings: undefined;
  Crisis: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

function BootSplash(): React.JSX.Element {
  return (
    <View style={styles.splash}>
      <ActivityIndicator color="#4f7cff" size="large" />
    </View>
  );
}

export function AppNavigator(): React.JSX.Element {
  // Tri-state: while "loading" a saved session may still be resolving from
  // disk — rendering Login in that window let a second account sign in over
  // a live one without any wipe running (the audit's login-flash race).
  const { authStatus, unlocked } = useSession();
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
          <Stack.Screen name="Entry" component={EntryScreen} options={{ title: "Today" }} />
          <Stack.Screen name="Insights" component={InsightsScreen} options={{ title: "Patterns" }} />
          <Stack.Screen name="Question" component={QuestionScreen} options={{ title: "One question" }} />
          <Stack.Screen name="Settings" component={SettingsScreen} options={{ title: "Settings" }} />
          {/* Crisis help: one navigation hop from every screen (offline,
              static content — see CrisisScreen). */}
          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />
        </>
      )}
    </Stack.Navigator>
  );
}

const styles = StyleSheet.create({
  splash: { flex: 1, backgroundColor: "#0f1115", alignItems: "center", justifyContent: "center" },
});
