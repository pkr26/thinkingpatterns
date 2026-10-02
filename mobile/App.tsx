import React, { useEffect, useState } from "react";
import { AppState, StyleSheet, View } from "react-native";
import { NavigationContainer } from "@react-navigation/native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { SessionProvider } from "./src/store";
import { AppNavigator } from "./src/navigation";
import { ThemeProvider, useTheme } from "./src/theme";
import { startNotificationPressRouting } from "./src/nativeFeatures";
import { applyStoredLanguageChoice } from "./src/languagePref";
import { ErrorBoundary } from "./src/ErrorBoundary";

/**
 * Privacy shield: while the app is backgrounded, the iOS app-switcher
 * snapshot would otherwise show the journal draft (or decrypted patterns) in
 * plain sight. An opaque overlay renders whenever the app is not active.
 */
export default function App(): React.JSX.Element {
  return (
    <ThemeProvider>
      {/* 2026-10-01 audit L-4: no componentDidCatch existed anywhere — any
          render throw white-screened the app with no crisis-resources
          escape hatch. Inside ThemeProvider so the fallback is themed. */}
      <ErrorBoundary>
        <ThemedApp />
      </ErrorBoundary>
    </ThemeProvider>
  );
}

/** Kept below ThemeProvider so the app-switcher shield tracks an explicit
 * light/dark setting too. Calling useTheme above its provider meant the
 * shield permanently followed only the OS, briefly flashing the wrong color
 * when a user chose an override. */
function ThemedApp(): React.JSX.Element {
  const t = useTheme();
  const [shielded, setShielded] = useState(AppState.currentState !== "active");

  useEffect(() => {
    // 2026-09-29 deep audit (P2): apply the stored language override
    // before the first meaningful render (unreadable storage keeps the
    // device-detected locale — boot never blocks on it).
    void applyStoredLanguageChoice();
    const sub = AppState.addEventListener("change", (state) => {
      setShielded(state !== "active");
    });
    return () => sub.remove();
  }, []);

  // Notification-tap routing (2026-09-27): a tap on the measure check-in
  // nudge queues its destination; the navigator opens the Measures screen
  // when the main flow is entered. Quiet no-op while the notification
  // module is unlinked in this build (the seam's own guarantee).
  useEffect(() => {
    void startNotificationPressRouting().catch(() => {});
  }, []);

  return (
    <SafeAreaProvider>
      <SessionProvider>
        <NavigationContainer>
          <AppNavigator />
          {shielded && <View style={[styles.shield, { backgroundColor: t.colors.bg }]} pointerEvents="none" />}
        </NavigationContainer>
      </SessionProvider>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  shield: {
    ...StyleSheet.absoluteFill,
  },
});
