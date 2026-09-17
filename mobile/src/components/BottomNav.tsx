/**
 * The persistent bottom navigation bar (2026-09-17).
 *
 * The audit's top mobile finding: navigation lived INSIDE the Entry
 * screen's scroll content — type a 300-word entry and reaching History
 * meant scrolling past your entire text. Every main screen now renders
 * this pinned bar below its scrolling content: same five destinations
 * plus the always-present "Get help" end-cap (crisis help stays one tap
 * from every screen, matching the navigation contract in
 * src/navigation.tsx).
 *
 * With no icon library available, hierarchy stays typographic (matching
 * NavRow's approach): the active destination carries the accent color and
 * a heavier weight; "Get help" keeps its distinct help surface. Labels
 * cap their font multiplier so large text cannot break the row.
 */
import React from "react";
import { KeyboardAvoidingView, Platform, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { useTheme } from "../theme";

export type NavDestination = "Entry" | "History" | "Insights" | "Question" | "Settings";

export interface BottomNavItem {
  key: NavDestination | "Crisis";
  label: string;
  help?: boolean;
}

export const BOTTOM_NAV_ITEMS: readonly BottomNavItem[] = [
  { key: "Entry", label: "Today" },
  { key: "History", label: "History" },
  { key: "Insights", label: "Patterns" },
  { key: "Question", label: "Question" },
  { key: "Settings", label: "Settings" },
  { key: "Crisis", label: "Get help", help: true },
] as const;

export function BottomNav({
  current,
  navigation,
}: {
  current: NavDestination | "none";
  navigation?: { navigate: (screen: string) => void };
}): React.JSX.Element {
  const t = useTheme();
  return (
    <View
      style={[styles.bar, { backgroundColor: t.colors.bg, borderTopColor: t.colors.border }]}
      accessibilityRole="tablist"
      accessibilityLabel="Main navigation"
    >
      {BOTTOM_NAV_ITEMS.map((item) => {
        const active = item.key === current;
        const help = item.help === true;
        return (
          <TouchableOpacity
            key={item.key}
            style={[
              styles.button,
              {
                backgroundColor: help ? t.colors.helpBg : active ? t.colors.card : "transparent",
                borderRadius: t.radius.md,
                minHeight: t.minTouch,
              },
            ]}
            onPress={() => navigation?.navigate(item.key)}
            accessibilityRole="tab"
            accessibilityState={active ? { selected: true } : undefined}
            accessibilityLabel={help ? "Get help — crisis resources" : item.label}
          >
            <Text
              maxFontSizeMultiplier={1.3}
              style={{
                color: help ? t.colors.text : active ? t.colors.accent : t.colors.muted,
                fontSize: 12,
                fontWeight: help ? "700" : active ? "700" : "600",
                textAlign: "center",
              }}
            >
              {item.label}
            </Text>
          </TouchableOpacity>
        );
      })}
    </View>
  );
}

/** Shared shell for the five main screens: scrolling content above, the
 *  persistent nav below. `keyboard` wraps children in the platform
 *  KeyboardAvoidingView (the Entry editor). */
export function MainShell({
  current,
  navigation,
  children,
  keyboard = false,
  keyboardBehavior,
}: {
  current: NavDestination | "none";
  navigation?: { navigate: (screen: string) => void };
  children: React.ReactNode;
  keyboard?: boolean;
  keyboardBehavior?: "padding" | undefined;
}): React.JSX.Element {
  const t = useTheme();
  const inner = <View style={styles.content}>{children}</View>;
  return (
    <View style={[styles.shell, { backgroundColor: t.colors.bg }]}>
      {keyboard ? (
        <KeyboardAvoidingView style={styles.content} behavior={keyboardBehavior}>
          {inner}
        </KeyboardAvoidingView>
      ) : (
        inner
      )}
      <BottomNav current={current} navigation={navigation} />
    </View>
  );
}

const styles = StyleSheet.create({
  shell: { flex: 1 },
  content: { flex: 1 },
  bar: {
    flexDirection: "row",
    gap: 4,
    borderTopWidth: StyleSheet.hairlineWidth,
    paddingHorizontal: 8,
    paddingTop: 6,
    paddingBottom: Platform.OS === "ios" ? 8 : 10,
  },
  button: { flex: 1, alignItems: "center", justifyContent: "center", paddingHorizontal: 2, paddingVertical: 8 },
});
