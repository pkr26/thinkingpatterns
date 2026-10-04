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
import { t as tr } from "./strings";

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

  componentDidCatch(): void {
    // A render exception can contain decrypted journal text, account ids,
    // or hostile payload fragments. Emit only a fixed local diagnostic.
    // eslint-disable-next-line no-console
    console.warn("render_error_boundary");
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
          {tr("app.crashTitle")}
        </Text>
        <Text style={[styles.body, { color: t.colors.muted }]}>
          {tr("app.crashBody")}
        </Text>
        <Pressable
          accessibilityRole="button"
          onPress={onRetry}
          style={[styles.button, { backgroundColor: t.colors.card }]}
        >
          <Text style={{ color: t.colors.text, fontWeight: "700" }}>{tr("app.crashRetry")}</Text>
        </Pressable>
        <Pressable
          accessibilityRole="link"
          onPress={() => Linking.openURL("https://findahelpline.com").catch(() => undefined)}
          style={[styles.button, { backgroundColor: t.colors.card }]}
        >
          <Text style={{ color: t.colors.muted }}>{tr("app.crashCrisis")}</Text>
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
