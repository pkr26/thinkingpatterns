/**
 * Root ErrorBoundary (2026-10-01 audit L-4): the mobile app had NO
 * componentDidCatch anywhere — any render-time throw (a hostile or simply
 * unexpected payload shape) white-screened the whole app. For this user
 * population the fallback must stay usable: a calm message, a restart
 * affordance, and — load-bearing — a crisis-resources escape hatch that
 * never depends on the crashed tree.
 */
import React from "react";
import { Linking, Pressable, StyleSheet, Text, View } from "react-native";
import { useTheme } from "./theme";

interface Props {
  children: React.ReactNode;
}

interface State {
  failed: boolean;
}

export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: unknown): void {
    // Local, best-effort diagnostics only: the message string never
    // contains journal plaintext (it is a render exception), and nothing
    // is transmitted anywhere.
    // eslint-disable-next-line no-console
    console.warn("render crashed; ErrorBoundary engaged:", String(error));
  }

  render(): React.JSX.Element {
    if (!this.state.failed) return this.props.children as React.JSX.Element;
    return <ErrorFallback onRetry={() => this.setState({ failed: false })} />;
  }
}

function ErrorFallback({ onRetry }: { onRetry: () => void }): React.JSX.Element {
  const t = useTheme();
  return (
      <View style={[styles.root, { backgroundColor: t.colors.bg }]}>
        <Text style={[styles.title, { color: t.colors.text }]}>
          Something went wrong
        </Text>
        <Text style={[styles.body, { color: t.colors.muted }]}>
          Your journal is safe and encrypted on this device. The screen
          failed to draw — restarting the app usually resolves it.
        </Text>
        <Pressable
          accessibilityRole="button"
          onPress={onRetry}
          style={[styles.button, { backgroundColor: t.colors.card }]}
        >
          <Text style={{ color: t.colors.text, fontWeight: "700" }}>Try again</Text>
        </Pressable>
        <Pressable
          accessibilityRole="link"
          onPress={() => Linking.openURL("https://findahelpline.com").catch(() => undefined)}
          style={[styles.button, { backgroundColor: t.colors.card }]}
        >
          <Text style={{ color: t.colors.muted }}>Crisis resources</Text>
        </Pressable>
      </View>
  );
}

const styles = StyleSheet.create({
  root: { flex: 1, alignItems: "center", justifyContent: "center", padding: 32, gap: 16 },
  title: { fontSize: 20, fontWeight: "700" },
  body: { fontSize: 14, textAlign: "center", lineHeight: 20 },
  button: { borderRadius: 12, paddingHorizontal: 20, paddingVertical: 12 },
});
