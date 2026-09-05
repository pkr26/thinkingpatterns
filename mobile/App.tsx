import React, { useEffect, useState } from "react";
import { AppState, StyleSheet, View } from "react-native";
import { NavigationContainer } from "@react-navigation/native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { SessionProvider } from "./src/store";
import { AppNavigator } from "./src/navigation";

/**
 * Privacy shield: while the app is backgrounded, the iOS app-switcher
 * snapshot would otherwise show the journal draft (or decrypted patterns) in
 * plain sight. An opaque overlay renders whenever the app is not active.
 */
export default function App(): React.JSX.Element {
  const [shielded, setShielded] = useState(AppState.currentState !== "active");

  useEffect(() => {
    const sub = AppState.addEventListener("change", (state) => {
      setShielded(state !== "active");
    });
    return () => sub.remove();
  }, []);

  return (
    <SafeAreaProvider>
      <SessionProvider>
        <NavigationContainer>
          <AppNavigator />
          {shielded && <View style={styles.shield} pointerEvents="none" />}
        </NavigationContainer>
      </SessionProvider>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  shield: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: "#0f1115",
  },
});
