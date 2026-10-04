import React, { useEffect, useState } from "react";
import { AppState, StyleSheet, View } from "react-native";
import { NavigationContainer } from "@react-navigation/native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { SessionProvider } from "./src/store";
import { AppNavigator, navigationRef } from "./src/navigation";
import { ThemeProvider, useTheme } from "./src/theme";
import { startNotificationPressRouting } from "./src/nativeFeatures";
import { applyStoredLanguageChoice } from "./src/languagePref";
import { notifyNavigationReady } from "./src/notificationRoute";
import { ErrorBoundary } from "./src/ErrorBoundary";

/**
 * Privacy shield: while the app is backgrounded, the iOS app-switcher
 * snapshot would otherwise show the journal draft (or decrypted patterns) in
 * plain sight. An opaque overlay renders whenever the app is not active.
 */
export default function App(): React.JSX.Element {
  return (
    <ThemeProvider>
      {/** Keep the fallback inside ThemeProvider and outside the screen tree. */}
      <ErrorBoundary>
        <ThemedApp />
      </ErrorBoundary>
    </ThemeProvider>
  );
}

/** Use the selected theme for the app-switcher privacy shield. */
function ThemedApp(): React.JSX.Element {
  const t = useTheme();
  const [languageReady, setLanguageReady] = useState(false);
  const [shielded, setShielded] = useState(AppState.currentState !== "active");

  useEffect(() => {
    // Apply the stored language before the first screen renders.
    // Unreadable storage preserves the detected device locale.
    let cancelled = false;
    void applyStoredLanguageChoice().finally(() => { if (!cancelled) setLanguageReady(true); });
    const sub = AppState.addEventListener("change", (state) => {
      setShielded(state !== "active");
    });
    return () => { cancelled = true; sub.remove(); };
  }, []);

  // Queue notification destinations until the unlocked navigator is ready.
  // Missing native notification support leaves routing inactive.
  useEffect(() => {
    let cancelled = false;
    let dispose: (() => void) | null = null;
    void startNotificationPressRouting().then((stop) => {
      if (cancelled) stop?.(); else dispose = stop;
    }).catch(() => {});
    return () => { cancelled = true; dispose?.(); };
  }, []);

  return (
    <SafeAreaProvider>
      <SessionProvider>
        <NavigationContainer ref={navigationRef} onReady={notifyNavigationReady}>
          {languageReady && <AppNavigator />}
          {shielded && <View style={[styles.shield, { backgroundColor: t.colors.bg }]} pointerEvents="auto" accessibilityViewIsModal importantForAccessibility="yes" accessibilityLabel="Fathom" />}
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
