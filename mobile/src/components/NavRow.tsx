/**
 * The bottom nav row shared by the main screens. With no icon library
 * available, hierarchy comes from typography and color alone: ordinary
 * destinations sit on card surfaces, and "Get help" gets the help surface +
 * a heavier label — unmistakable without being alarming. Nav labels cap
 * their font multiplier: very large text must not break the row apart.
 */
import React from "react";
import { StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { useTheme } from "../theme";

export interface NavItem {
  label: string;
  onPress: () => void;
  /** "help" marks the crisis-resources action (distinct surface + weight). */
  tone?: "default" | "help";
  accessibilityLabel?: string;
}

export function NavRow({ items }: { items: NavItem[] }): React.JSX.Element {
  const t = useTheme();
  return (
    <View style={styles.row}>
      {items.map((item) => {
        const help = item.tone === "help";
        return (
          <TouchableOpacity
            key={item.label}
            style={[
              styles.button,
              {
                backgroundColor: help ? t.colors.helpBg : t.colors.card,
                borderRadius: t.radius.md,
                minHeight: t.minTouch,
              },
            ]}
            onPress={item.onPress}
            accessibilityRole="button"
            accessibilityLabel={item.accessibilityLabel ?? item.label}
          >
            <Text
              maxFontSizeMultiplier={1.3}
              style={{
                color: help ? t.colors.text : t.colors.accent,
                fontSize: 14,
                fontWeight: help ? "700" : "600",
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

const styles = StyleSheet.create({
  row: { flexDirection: "row", gap: 10 },
  button: { flex: 1, padding: 14, alignItems: "center", justifyContent: "center" },
});
