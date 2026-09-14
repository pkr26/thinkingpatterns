/**
 * Transient inline confirmations — the fix for the save-feedback inversion
 * the audit found (online save = silent clear, offline save = interruptive
 * modal). Success is now a small status line that appears where the user is
 * already looking and clears itself; Alert stays reserved for failures the
 * user must act on.
 */
import React from "react";
import { StyleSheet, Text, View } from "react-native";
import { useTheme } from "../theme";

export type InlineStatusTone = "ok" | "neutral";

/** A one-line status ("Saved ✓" / "Saved — will sync when online"). The
 *  parent owns the lifetime: set the message, clear it after a moment.
 *  Announced politely to screen readers (live region). */
export function InlineStatus({ message, tone = "ok" }: { message: string | null; tone?: InlineStatusTone }) {
  const t = useTheme();
  if (!message) return null;
  return (
    <View
      style={[styles.status, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md }]}
      accessibilityLiveRegion="polite"
      accessibilityRole="text"
      accessibilityLabel={message}
    >
      <Text style={{ color: tone === "ok" ? t.colors.success : t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
        {message}
      </Text>
    </View>
  );
}

/** A small persistent pill ("Draft restored") — calmer than a dialog, more
 *  durable than a status line. */
export function NoticeChip({ text, accessibilityLabel }: { text: string; accessibilityLabel?: string }) {
  const t = useTheme();
  return (
    <View
      style={[styles.chip, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}
      accessibilityRole="text"
      accessibilityLabel={accessibilityLabel ?? text}
    >
      <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  status: { paddingVertical: 10, paddingHorizontal: 14, alignItems: "center" },
  chip: { alignSelf: "flex-start", paddingVertical: 6, paddingHorizontal: 12 },
});
